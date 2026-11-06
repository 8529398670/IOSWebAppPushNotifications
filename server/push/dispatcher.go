package push

import (
	errors "errors"
	fmt "fmt"
	http "net/http"
	sync "sync"
	atomic "sync/atomic"
	time "time"

	config "ipb/server/config"
	db "ipb/server/db"
	models "ipb/server/models"
)

const (
	// JobName and JobInterval put the outbox on the Jobs screen. A send does
	// not wait for the interval: Nudge starts a run straight away.
	JobName     = "push"
	JobInterval = 30 * time.Second

	// sendsPerPass bounds how many deliveries one pass loads, and
	// sendersPerPass how many go at once, so one dead endpoint waiting out its
	// timeout holds up one slot rather than the queue.
	sendsPerPass   = 200
	sendersPerPass = 8
	// holdFor is how far ahead a run waits for the next retry rather than
	// ending. The registry only looks every 30 seconds, and the first retries
	// should not have to wait for that.
	holdFor = 20 * time.Second
	// runLimit ends a run that keeps finding work, so the Jobs screen sees one
	// finish.
	runLimit = 4 * time.Minute

	maxPayloadTrims = 12
)

// retryAfter is how long each failed attempt waits. Past the end the delivery is
// given up on. A message that matters this soon has little use after hours.
var retryAfter = []time.Duration{ 5 * time.Second , 15 * time.Second , time.Minute , 5 * time.Minute , 15 * time.Minute , time.Hour }

// Dispatcher works through the outbox. It is separate from the webhooks one,
// which stops when webhooks are off, sends one at a time and backs off for hours.
type Dispatcher struct {
	store    *db.Store
	settings *config.Holder
	client   *http.Client
	// allow is AllowedEndpoint, and only a test replaces it.
	allow func( string ) bool
	wake  chan struct{}
	stop  chan struct{}
	once  sync.Once

	// RunNow is set by main.go to the registry's way of starting this job.
	RunNow func()
}

// New makes a Dispatcher that sends over the guarded client.
func New( store *db.Store , settings *config.Holder ) ( dispatcher *Dispatcher ) {
	dispatcher = &Dispatcher{
		store:    store,
		settings: settings,
		client:   NewClient(),
		allow:    AllowedEndpoint,
		wake:     make( chan struct{} , 1 ),
		stop:     make( chan struct{} ),
	}
	return
}

// Nudge says there is something to send. A run already going sees wake; if the
// run ends in the instant after looking, the next tick picks it up.
func ( dispatcher *Dispatcher ) Nudge() {
	select {
	case dispatcher.wake <- struct{}{}:
	default:
	}
	if dispatcher.RunNow != nil { dispatcher.RunNow() }
}

// Close ends a waiting run, so shutdown does not sit out holdFor.
func ( dispatcher *Dispatcher ) Close() {
	dispatcher.once.Do( func() { close( dispatcher.stop ) } )
}

type tally struct {
	sent   atomic.Int64
	failed atomic.Int64
	gone   atomic.Int64
}

// Run is the job. Only trouble with the database fails it: a push service being
// down is what the retries are for.
func ( dispatcher *Dispatcher ) Run() ( note string , err error ) {
	counts := &tally{}
	defer func() {
		note = fmt.Sprintf( "sent %d, gave up on %d, dropped %d dead devices" , counts.sent.Load() , counts.failed.Load() , counts.gone.Load() )
	}()

	cfg := dispatcher.settings.Get()
	public_key , private_key , err := models.LoadVAPIDKeys( dispatcher.store , cfg.SecretKey )
	if err != nil { return }
	sender := &Sender{ PublicKey: public_key , PrivateKey: private_key , Subject: cfg.Push.Subject , Client: dispatcher.client , allow: dispatcher.allow }

	deadline := time.Now().Add( runLimit )
	for time.Now().Before( deadline ) {
		now := time.Now().UTC()
		if _ , err = models.QueueDueRepeats( dispatcher.store , now ); err != nil { return }
		due , next , list_err := models.DuePushDeliveries( dispatcher.store , now , sendsPerPass )
		if list_err != nil {
			err = list_err
			return
		}
		if len( due ) > 0 {
			if err = dispatcher.sendAll( sender , cfg.URL , due , counts ); err != nil { return }
			continue
		}

		repeat_at , repeat_err := models.NextRepeatAt( dispatcher.store )
		if repeat_err != nil {
			err = repeat_err
			return
		}
		if next.IsZero() || ( repeat_at.IsZero() == false && repeat_at.Before( next ) ) { next = repeat_at }
		if next.IsZero() || time.Until( next ) > holdFor {
			select {
			case <-dispatcher.wake:
				continue
			default:
				return
			}
		}
		timer := time.NewTimer( time.Until( next ) )
		select {
		case <-timer.C:
		case <-dispatcher.wake:
			timer.Stop()
		case <-dispatcher.stop:
			timer.Stop()
			return
		}
	}
	return
}

func ( dispatcher *Dispatcher ) sendAll( sender *Sender , base_url string , due []*models.PushDelivery , counts *tally ) ( err error ) {
	slots := make( chan struct{} , sendersPerPass )
	failures := make( chan error , len( due ) )
	var waiting sync.WaitGroup
	for _ , delivery := range due {
		waiting.Add( 1 )
		slots <- struct{}{}
		go func() {
			defer waiting.Done()
			defer func() { <-slots }()
			if deliver_err := dispatcher.deliver( sender , base_url , delivery , counts ); deliver_err != nil {
				failures <- deliver_err
			}
		}()
	}
	waiting.Wait()
	close( failures )
	for failure := range failures {
		err = errors.Join( err , failure )
	}
	return
}

// deliver makes one attempt and decides what becomes of the row.
func ( dispatcher *Dispatcher ) deliver( sender *Sender , base_url string , delivery *models.PushDelivery , counts *tally ) ( err error ) {
	now := time.Now().UTC()
	if now.After( delivery.ExpiresAt ) {
		counts.failed.Add( 1 )
		err = models.FinishPushDelivery( dispatcher.store , delivery.ID )
		return
	}
	subscription , get_err := models.GetPushSubscription( dispatcher.store , delivery.SubscriptionID )
	if errors.Is( get_err , db.ErrNotFound ) {
		err = models.FinishPushDelivery( dispatcher.store , delivery.ID )
		return
	}
	if get_err != nil {
		err = get_err
		return
	}
	item , item_err := models.GetInboxItem( dispatcher.store , delivery.UserID , delivery.ItemID )
	if errors.Is( item_err , models.ErrInboxGone ) || ( item_err == nil && item.Deleted() ) {
		err = models.FinishPushDelivery( dispatcher.store , delivery.ID )
		return
	}
	if item_err != nil {
		err = item_err
		return
	}
	badge , err := models.UnreadCount( dispatcher.store , delivery.UserID )
	if err != nil { return }
	payload , err := Payload( NotificationFor( item , base_url , badge ) )
	if err != nil { return }

	result , send_err := sender.Send( subscription , payload , delivery.ExpiresAt.Sub( now ) , UrgencyFor( item.Priority ) )
	switch {
	case send_err == nil && result.Gone:
		counts.gone.Add( 1 )
		err = models.DeletePushSubscription( dispatcher.store , subscription.ID )
	case send_err == nil && result.Status >= 200 && result.Status < 300:
		counts.sent.Add( 1 )
		err = models.FinishPushDelivery( dispatcher.store , delivery.ID )
	case send_err != nil || result.Status == http.StatusTooManyRequests || result.Status >= 500:
		if delivery.Attempts >= len( retryAfter ) {
			counts.failed.Add( 1 )
			err = models.FinishPushDelivery( dispatcher.store , delivery.ID )
			return
		}
		err = models.RetryPushDelivery( dispatcher.store , delivery.ID , now.Add( retryAfter[ delivery.Attempts ] ) )
	default:
		// Any other refusal will not change by asking again.
		counts.failed.Add( 1 )
		err = models.FinishPushDelivery( dispatcher.store , delivery.ID )
	}
	return
}
