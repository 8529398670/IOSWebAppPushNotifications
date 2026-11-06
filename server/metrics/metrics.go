// Package metrics keeps the numbers GET /metrics reports, and writes them in
// Prometheus's text format. That format is a few lines of printing, so there
// is no client library behind this.
//
// Everything is labelled by a short fixed list, never by path: a path has as
// many values as anyone cares to request, and a scraper keeps a series for each
// one forever.
package metrics

import (
	fmt "fmt"
	io "io"
	sort "sort"
	strconv "strconv"
	strings "strings"
	sync "sync"
	atomic "sync/atomic"
	time "time"
)

var buckets = []float64{ 0.005 , 0.01 , 0.025 , 0.05 , 0.1 , 0.25 , 0.5 , 1 , 2.5 , 5 , 10 }

var knownMethods = map[ string ]bool{
	"GET": true , "HEAD": true , "POST": true , "PUT": true ,
	"PATCH": true , "DELETE": true , "OPTIONS": true ,
}

type requestKey struct {
	method string
	class  string
}

// Recorder is safe to use from every request at once.
type Recorder struct {
	started  time.Time
	inFlight atomic.Int64

	lock     sync.Mutex
	requests map[ requestKey ]uint64
	counts   []uint64
	sum      float64
	total    uint64
}

func New() ( recorder *Recorder ) {
	recorder = &Recorder{
		started:  time.Now(),
		requests: map[ requestKey ]uint64{},
		counts:   make( []uint64 , len( buckets ) ),
	}
	return
}

func ( recorder *Recorder ) Begin() { recorder.inFlight.Add( 1 ) }

func ( recorder *Recorder ) End() { recorder.inFlight.Add( -1 ) }

// Observe records one finished request. timed is false for one whose duration
// means nothing, which still counts as a request.
func ( recorder *Recorder ) Observe( method string , status int , seconds float64 , timed bool ) {
	if knownMethods[ method ] == false {
		method = "OTHER"
	}
	key := requestKey{ method: method , class: strconv.Itoa( status / 100 ) + "xx" }
	recorder.lock.Lock()
	defer recorder.lock.Unlock()
	recorder.requests[ key ] += 1
	if timed == false { return }
	recorder.sum += seconds
	recorder.total += 1
	for index , bound := range buckets {
		if seconds <= bound {
			recorder.counts[ index ] += 1
		}
	}
}

// Job is one background job's results, for the gauges below.
type Job struct {
	Name        string
	LastSuccess *time.Time
	LastFailure *time.Time
}

// Extra is what the recorder cannot know for itself.
type Extra struct {
	LogsDropped int64
	Jobs        []Job
}

// Write prints every metric family. Each has its HELP and TYPE even with no
// samples yet, so a scrape looks the same from the first request.
func ( recorder *Recorder ) Write( out io.Writer , extra Extra ) {
	recorder.lock.Lock()
	requests := make( map[ requestKey ]uint64 , len( recorder.requests ) )
	for key , count := range recorder.requests {
		requests[ key ] = count
	}
	counts := append( []uint64( nil ) , recorder.counts... )
	sum , total := recorder.sum , recorder.total
	recorder.lock.Unlock()

	family( out , "app_http_requests_total" , "counter" , "Requests answered, by method and status class." )
	keys := make( []requestKey , 0 , len( requests ) )
	for key := range requests {
		keys = append( keys , key )
	}
	sort.Slice( keys , func( a int , b int ) ( less bool ) {
		less = keys[ a ].method + keys[ a ].class < keys[ b ].method + keys[ b ].class
		return
	} )
	for _ , key := range keys {
		fmt.Fprintf( out , "app_http_requests_total{method=%s,status_class=%s} %d\n" , label( key.method ) , label( key.class ) , requests[ key ] )
	}

	family( out , "app_http_request_duration_seconds" , "histogram" , "How long requests took." )
	for index , bound := range buckets {
		fmt.Fprintf( out , "app_http_request_duration_seconds_bucket{le=%s} %d\n" , label( strconv.FormatFloat( bound , 'f' , -1 , 64 ) ) , counts[ index ] )
	}
	fmt.Fprintf( out , "app_http_request_duration_seconds_bucket{le=\"+Inf\"} %d\n" , total )
	fmt.Fprintf( out , "app_http_request_duration_seconds_sum %g\n" , sum )
	fmt.Fprintf( out , "app_http_request_duration_seconds_count %d\n" , total )

	family( out , "app_http_requests_in_flight" , "gauge" , "Requests being answered right now." )
	fmt.Fprintf( out , "app_http_requests_in_flight %d\n" , recorder.inFlight.Load() )

	family( out , "app_uptime_seconds" , "gauge" , "Seconds since the server started." )
	fmt.Fprintf( out , "app_uptime_seconds %g\n" , time.Since( recorder.started ).Seconds() )

	family( out , "app_logs_dropped_total" , "counter" , "Activity log entries lost because the writer fell behind." )
	fmt.Fprintf( out , "app_logs_dropped_total %d\n" , extra.LogsDropped )

	family( out , "app_job_last_success_timestamp_seconds" , "gauge" , "When each background job last succeeded." )
	for _ , job := range extra.Jobs {
		if job.LastSuccess != nil {
			fmt.Fprintf( out , "app_job_last_success_timestamp_seconds{job=%s} %d\n" , label( job.Name ) , job.LastSuccess.Unix() )
		}
	}

	family( out , "app_job_last_failure_timestamp_seconds" , "gauge" , "When each background job last failed." )
	for _ , job := range extra.Jobs {
		if job.LastFailure != nil {
			fmt.Fprintf( out , "app_job_last_failure_timestamp_seconds{job=%s} %d\n" , label( job.Name ) , job.LastFailure.Unix() )
		}
	}
}

func family( out io.Writer , name string , kind string , help string ) {
	fmt.Fprintf( out , "# HELP %s %s\n# TYPE %s %s\n" , name , help , name , kind )
}

var labelEscapes = strings.NewReplacer( `\` , `\\` , `"` , `\"` , "\n" , `\n` )

func label( value string ) ( quoted string ) {
	quoted = `"` + labelEscapes.Replace( value ) + `"`
	return
}
