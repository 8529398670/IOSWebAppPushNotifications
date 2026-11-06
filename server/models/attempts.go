package models

import (
	sync "sync"
	time "time"
)

// AttemptGuard limits wrong guesses at anything a person types: a PIN, a
// password, a two-factor code. Six digits is a million guesses, and four is
// ten thousand, so without this those are decoration. max_failures misses
// lock a key for AttemptLockout.
//
// In memory, like the rate limiter -- so it resets on restart and is per
// replica. It is a brake on guessing, not a record of anything.
type AttemptGuard[ K comparable ] struct {
	mu           sync.Mutex
	max_failures int
	failures     map[ K ]int
	until        map[ K ]time.Time
}

const (
	AttemptMaxFailures = 5
	AttemptLockout     = 15 * time.Minute
	// Keys can be anything a stranger typed, so what is remembered has to be
	// bounded. Past this an arbitrary count is forgotten.
	attemptMaxEntries = 10000
)

func NewAttemptGuard[ K comparable ]( max_failures int ) ( guard *AttemptGuard[ K ] ) {
	guard = &AttemptGuard[ K ]{ max_failures: max_failures , failures: map[ K ]int{} , until: map[ K ]time.Time{} }
	return
}

func ( guard *AttemptGuard[ K ] ) Locked( key K ) ( result bool ) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	until , found := guard.until[ key ]
	if found == false { return }
	result = time.Now().Before( until )
	if result == false {
		delete( guard.until , key )
	}
	return
}

func ( guard *AttemptGuard[ K ] ) Record( key K , ok bool ) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if ok {
		delete( guard.failures , key )
		return
	}
	guard.failures[ key ]++
	if guard.failures[ key ] >= guard.max_failures {
		guard.until[ key ] = time.Now().Add( AttemptLockout )
		delete( guard.failures , key )
	}
	guard.trim()
}

func ( guard *AttemptGuard[ K ] ) trim() {
	if len( guard.until ) > attemptMaxEntries {
		now := time.Now()
		for key , until := range guard.until {
			if until.Before( now ) {
				delete( guard.until , key )
			}
		}
	}
	for key := range guard.failures {
		if len( guard.failures ) <= attemptMaxEntries { break }
		delete( guard.failures , key )
	}
	for key := range guard.until {
		if len( guard.until ) <= attemptMaxEntries { break }
		delete( guard.until , key )
	}
}
