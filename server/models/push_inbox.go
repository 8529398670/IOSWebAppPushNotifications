package models

import (
	hex "encoding/hex"
	errors "errors"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

const (
	PriorityInboxOnly = -2
	PrioritySilent    = -1
	PriorityNormal    = 0
	PriorityHigh      = 1
	PriorityRepeat    = 2

	// DefaultPushTTL is how long a push service holds what it cannot deliver.
	DefaultPushTTL = 7 * 24 * time.Hour
	MaxPushTTL     = 28 * 24 * time.Hour
)

var ErrInboxGone = errors.New( "no such message" )

// OutgoingMessage is what a send asked for.
type OutgoingMessage struct {
	Title    string
	Body     string
	URL      string
	URLTitle string
	Priority int
	TTL      time.Duration
	// How often a priority 2 message repeats, and for how long.
	RepeatEvery time.Duration
	RepeatFor   time.Duration
}

// InboxItem is one message in one person's inbox. It copies the app's name so a
// message keeps saying who sent it after the app is renamed or deleted.
//
// The key is the user id then a sequence, so one person's rows sit together in
// send order, and the id, which is that key in hex, says whose row it is: a
// person can only ever name their own.
type InboxItem struct {
	ID        string     `json:"id"`
	UserID    uint64     `json:"user_id"`
	RequestID string     `json:"request_id"`
	AppID     string     `json:"app_id"`
	AppName   string     `json:"app_name"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	URL       string     `json:"url,omitempty"`
	URLTitle  string     `json:"url_title,omitempty"`
	Priority  int        `json:"priority"`
	CreatedAt time.Time  `json:"created_at"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
	SoftDelete
}

// PushDelivery is one item on its way to one device. It holds ids rather than a
// finished request because a signature expires and the badge count changes.
// Rows are deleted as they finish, so the outbox stays small.
type PushDelivery struct {
	ID             string    `json:"id"`
	SubscriptionID string    `json:"subscription_id"`
	ItemID         string    `json:"item_id"`
	UserID         uint64    `json:"user_id"`
	Attempts       int       `json:"attempts"`
	NextAttemptAt  time.Time `json:"next_attempt_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// PushRepeat keeps a priority 2 message coming until it is read or runs out.
type PushRepeat struct {
	ItemID string        `json:"item_id"`
	UserID uint64        `json:"user_id"`
	NextAt time.Time     `json:"next_at"`
	Until  time.Time     `json:"until"`
	Every  time.Duration `json:"every"`
	TTL    time.Duration `json:"ttl"`
}

func inboxKey( user_id uint64 , sequence uint64 ) ( key []byte ) {
	key = append( encryption.Uint64ToBytes( user_id ) , encryption.Uint64ToBytes( sequence )... )
	return
}

// ownInboxKey decodes an item id, refusing one that is not this person's.
func ownInboxKey( user_id uint64 , item_id string ) ( key []byte , err error ) {
	key , decode_err := hex.DecodeString( item_id )
	if decode_err != nil || len( key ) != 16 || string( key[ :8 ] ) != string( encryption.Uint64ToBytes( user_id ) ) {
		err = ErrInboxGone
	}
	return
}

func addDeliveriesTx( tx *db.Tx , item_id string , user_id uint64 , subscriptions []*PushSubscription , expires time.Time ) ( err error ) {
	now := time.Now().UTC()
	for _ , subscription := range subscriptions {
		delivery := &PushDelivery{
			ID:             encryption.GenerateURLToken( 12 ),
			SubscriptionID: subscription.ID,
			ItemID:         item_id,
			UserID:         user_id,
			NextAttemptAt:  now,
			ExpiresAt:      expires,
		}
		if err = tx.Put( db.BucketPushDeliveries , []byte( delivery.ID ) , delivery ); err != nil { return }
	}
	return
}

func subscriptionsByUserTx( tx *db.Tx ) ( result map[uint64][]*PushSubscription , err error ) {
	result = map[uint64][]*PushSubscription{}
	err = tx.ForEach( db.BucketPushSubscriptions ,
		func() any { return &PushSubscription{} } ,
		func( _ []byte , item any ) bool {
			subscription := item.( *PushSubscription )
			result[ subscription.UserID ] = append( result[ subscription.UserID ] , subscription )
			return true
		} )
	return
}

// EnqueueMessage puts a message in each person's inbox and queues its pushes,
// all in one transaction, so a failure leaves nothing half sent. A disabled
// account gets nothing, and someone who muted the app gets the inbox entry
// without the push. reached is who it landed with, for their open pages.
func EnqueueMessage( store *db.Store , app *PushApp , user_ids []uint64 , message OutgoingMessage ) ( request_id string , reached []uint64 , err error ) {
	request_id = encryption.GenerateURLToken( 12 )
	now := time.Now().UTC()
	expires := now.Add( message.TTL )
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		devices , tx_err := subscriptionsByUserTx( tx )
		if tx_err != nil { return }
		for _ , user_id := range user_ids {
			user := &User{}
			if get_err := tx.Get( db.BucketUsers , encryption.Uint64ToBytes( user_id ) , user ); get_err != nil || user.Disabled() { continue }
			prefs , prefs_err := prefsTx( tx , user_id )
			if prefs_err != nil {
				tx_err = prefs_err
				return
			}
			sequence , sequence_err := tx.NextSequence( db.BucketInbox )
			if sequence_err != nil {
				tx_err = sequence_err
				return
			}
			key := inboxKey( user_id , sequence )
			item := &InboxItem{
				ID:        hex.EncodeToString( key ),
				UserID:    user_id,
				RequestID: request_id,
				AppID:     app.ID,
				AppName:   app.Name,
				Title:     message.Title,
				Body:      message.Body,
				URL:       message.URL,
				URLTitle:  message.URLTitle,
				Priority:  message.Priority,
				CreatedAt: now,
			}
			if tx_err = tx.Put( db.BucketInbox , key , item ); tx_err != nil { return }
			reached = append( reached , user_id )

			if message.Priority == PriorityInboxOnly || prefs.Muted( app.ID ) { continue }
			if tx_err = addDeliveriesTx( tx , item.ID , user_id , devices[ user_id ] , expires ); tx_err != nil { return }
			if message.Priority == PriorityRepeat {
				repeat := &PushRepeat{
					ItemID: item.ID,
					UserID: user_id,
					NextAt: now.Add( message.RepeatEvery ),
					Until:  now.Add( message.RepeatFor ),
					Every:  message.RepeatEvery,
					TTL:    message.RepeatEvery,
				}
				if tx_err = tx.Put( db.BucketPushRepeats , []byte( item.ID ) , repeat ); tx_err != nil { return }
			}
		}
		return
	} )
	if err != nil {
		request_id = ""
		reached = nil
	}
	return
}

// GetInboxItem loads one of a person's messages by its id.
func GetInboxItem( store *db.Store , user_id uint64 , item_id string ) ( item *InboxItem , err error ) {
	key , err := ownInboxKey( user_id , item_id )
	if err != nil { return }
	found := &InboxItem{}
	if get_err := store.Get( db.BucketInbox , key , found ); get_err != nil {
		err = ErrInboxGone
		if errors.Is( get_err , db.ErrNotFound ) == false { err = get_err }
		return
	}
	item = found
	return
}

// ListInbox is a person's messages, newest first. app_id narrows it to one app.
func ListInbox( store *db.Store , user_id uint64 , app_id string ) ( items []*InboxItem , err error ) {
	items = []*InboxItem{}
	err = store.ForEachPrefix( db.BucketInbox , encryption.Uint64ToBytes( user_id ) ,
		func() any { return &InboxItem{} } ,
		func( _ []byte , item any ) bool {
			found := item.( *InboxItem )
			if found.Deleted() == false && ( app_id == "" || found.AppID == app_id ) {
				items = append( items , found )
			}
			return true
		} )
	for left , right := 0 , len( items ) - 1; left < right; left , right = left + 1 , right - 1 {
		items[ left ] , items[ right ] = items[ right ] , items[ left ]
	}
	return
}

// UnreadCount is the number on the Home Screen icon.
func UnreadCount( store *db.Store , user_id uint64 ) ( count int , err error ) {
	err = store.ForEachPrefix( db.BucketInbox , encryption.Uint64ToBytes( user_id ) ,
		func() any { return &InboxItem{} } ,
		func( _ []byte , item any ) bool {
			found := item.( *InboxItem )
			if found.Deleted() == false && found.ReadAt == nil { count += 1 }
			return true
		} )
	return
}

// MarkInboxRead marks one message read, and reading a priority 2 message is
// what stops it repeating.
func MarkInboxRead( store *db.Store , user_id uint64 , item_id string ) ( err error ) {
	key , err := ownInboxKey( user_id , item_id )
	if err != nil { return }
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		item := &InboxItem{}
		tx_err = tx.Get( db.BucketInbox , key , item )
		if errors.Is( tx_err , db.ErrNotFound ) { tx_err = ErrInboxGone }
		if tx_err != nil { return }
		tx_err = markReadTx( tx , key , item )
		return
	} )
	return
}

func markReadTx( tx *db.Tx , key []byte , item *InboxItem ) ( err error ) {
	if item.ReadAt == nil {
		now := time.Now().UTC()
		item.ReadAt = &now
		if err = tx.Put( db.BucketInbox , key , item ); err != nil { return }
	}
	err = tx.Delete( db.BucketPushRepeats , []byte( item.ID ) )
	return
}

// MarkAllInboxRead clears everything unread for a person.
func MarkAllInboxRead( store *db.Store , user_id uint64 ) ( err error ) {
	unread , err := ListInbox( store , user_id , "" )
	if err != nil { return }
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		for _ , item := range unread {
			key , decode_err := ownInboxKey( user_id , item.ID )
			if decode_err != nil {
				tx_err = decode_err
				return
			}
			if tx_err = markReadTx( tx , key , item ); tx_err != nil { return }
		}
		return
	} )
	return
}

func updateInboxItem( store *db.Store , user_id uint64 , item_id string , mutate func( item *InboxItem ) error ) ( err error ) {
	key , err := ownInboxKey( user_id , item_id )
	if err != nil { return }
	err = store.UpdateValue( db.BucketInbox , key ,
		func() any { return &InboxItem{} } ,
		func( item any ) ( mutate_err error ) {
			mutate_err = mutate( item.( *InboxItem ) )
			return
		} )
	if errors.Is( err , db.ErrNotFound ) { err = ErrInboxGone }
	return
}

// DeleteInboxItem hides a message, and stops it repeating.
func DeleteInboxItem( store *db.Store , user_id uint64 , item_id string ) ( err error ) {
	err = updateInboxItem( store , user_id , item_id , func( item *InboxItem ) ( mutate_err error ) {
		item.markDeleted( user_id )
		return
	} )
	if err != nil { return }
	err = store.Delete( db.BucketPushRepeats , []byte( item_id ) )
	return
}

func RestoreInboxItem( store *db.Store , user_id uint64 , item_id string ) ( err error ) {
	err = updateInboxItem( store , user_id , item_id , func( item *InboxItem ) ( mutate_err error ) {
		mutate_err = item.unmarkDeleted( user_id , false )
		return
	} )
	return
}

// PurgeInbox removes messages older than keep, and anything deleted past its
// undo window.
func PurgeInbox( store *db.Store , keep time.Duration ) ( removed int , err error ) {
	cutoff := time.Now().UTC().Add( -keep )
	removed , err = store.DeleteWhere( db.BucketInbox ,
		func() any { return &InboxItem{} } ,
		func( _ []byte , item any ) bool {
			found := item.( *InboxItem )
			return found.CreatedAt.Before( cutoff ) || found.deletedLongAgo()
		} )
	return
}

// DuePushDeliveries is what can be sent now, up to limit. next is the soonest
// time anything else in the outbox falls due, zero when it is empty.
func DuePushDeliveries( store *db.Store , now time.Time , limit int ) ( due []*PushDelivery , next time.Time , err error ) {
	err = store.ForEach( db.BucketPushDeliveries ,
		func() any { return &PushDelivery{} } ,
		func( _ []byte , item any ) bool {
			delivery := item.( *PushDelivery )
			if delivery.NextAttemptAt.After( now ) {
				if next.IsZero() || delivery.NextAttemptAt.Before( next ) { next = delivery.NextAttemptAt }
				return true
			}
			if len( due ) < limit { due = append( due , delivery ) }
			return true
		} )
	return
}

// RetryPushDelivery puts a delivery back for later.
func RetryPushDelivery( store *db.Store , delivery_id string , at time.Time ) ( err error ) {
	err = store.UpdateValue( db.BucketPushDeliveries , []byte( delivery_id ) ,
		func() any { return &PushDelivery{} } ,
		func( item any ) ( mutate_err error ) {
			delivery := item.( *PushDelivery )
			delivery.Attempts += 1
			delivery.NextAttemptAt = at
			return
		} )
	return
}

// FinishPushDelivery takes a delivery off the outbox, however it went.
func FinishPushDelivery( store *db.Store , delivery_id string ) ( err error ) {
	err = store.Delete( db.BucketPushDeliveries , []byte( delivery_id ) )
	return
}

// QueueDueRepeats sends priority 2 messages round again. One that has run out
// stops, read or not. queued is how many pushes went on the outbox.
func QueueDueRepeats( store *db.Store , now time.Time ) ( queued int , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		repeats := []*PushRepeat{}
		tx_err = tx.ForEach( db.BucketPushRepeats ,
			func() any { return &PushRepeat{} } ,
			func( _ []byte , item any ) bool {
				repeat := item.( *PushRepeat )
				if repeat.NextAt.After( now ) == false { repeats = append( repeats , repeat ) }
				return true
			} )
		if tx_err != nil || len( repeats ) == 0 { return }
		devices , tx_err := subscriptionsByUserTx( tx )
		if tx_err != nil { return }
		for _ , repeat := range repeats {
			if now.After( repeat.Until ) {
				if tx_err = tx.Delete( db.BucketPushRepeats , []byte( repeat.ItemID ) ); tx_err != nil { return }
				continue
			}
			if tx_err = addDeliveriesTx( tx , repeat.ItemID , repeat.UserID , devices[ repeat.UserID ] , now.Add( repeat.TTL ) ); tx_err != nil { return }
			queued += len( devices[ repeat.UserID ] )
			repeat.NextAt = now.Add( repeat.Every )
			if tx_err = tx.Put( db.BucketPushRepeats , []byte( repeat.ItemID ) , repeat ); tx_err != nil { return }
		}
		return
	} )
	if err != nil { queued = 0 }
	return
}

// NextRepeatAt is when the soonest repeat falls due, zero when there are none.
func NextRepeatAt( store *db.Store ) ( next time.Time , err error ) {
	err = store.ForEach( db.BucketPushRepeats ,
		func() any { return &PushRepeat{} } ,
		func( _ []byte , item any ) bool {
			repeat := item.( *PushRepeat )
			if next.IsZero() || repeat.NextAt.Before( next ) { next = repeat.NextAt }
			return true
		} )
	return
}
