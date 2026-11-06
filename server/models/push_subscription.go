package models

import (
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// SubscriptionUserAgentMax caps what is kept of a browser's user agent.
const SubscriptionUserAgentMax = 200

// PushSubscription is one device's way of being reached. It belongs to the
// account, not the session, so a phone keeps getting notifications after the
// session that subscribed it has ended. That is what a person wants from a
// phone they rarely open, and it is why the devices list exists: ending a
// session does not stop pushes, and removing the device does.
type PushSubscription struct {
	ID        string    `json:"id"`
	UserID    uint64    `json:"user_id"`
	Endpoint  string    `json:"endpoint"`
	P256dh    string    `json:"p256dh"`
	Auth      string    `json:"auth"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}

// SubscriptionID is the id of the row for an endpoint.
func SubscriptionID( endpoint string ) ( id string ) {
	id = encryption.Sha256Hex( endpoint )
	return
}

// SavePushSubscription stores a subscription under its endpoint, so a device
// subscribing again replaces its old row, even when someone else signed in.
func SavePushSubscription( store *db.Store , subscription *PushSubscription ) ( err error ) {
	subscription.ID = SubscriptionID( subscription.Endpoint )
	subscription.CreatedAt = time.Now().UTC()
	err = store.Put( db.BucketPushSubscriptions , []byte( subscription.ID ) , subscription )
	return
}

// GetPushSubscription loads one row; db.ErrNotFound when it has gone.
func GetPushSubscription( store *db.Store , subscription_id string ) ( subscription *PushSubscription , err error ) {
	found := &PushSubscription{}
	if err = store.Get( db.BucketPushSubscriptions , []byte( subscription_id ) , found ); err != nil { return }
	subscription = found
	return
}

// PushSubscriptionsFor is every device one person has.
func PushSubscriptionsFor( store *db.Store , user_id uint64 ) ( result []*PushSubscription , err error ) {
	result = []*PushSubscription{}
	err = store.ForEach( db.BucketPushSubscriptions ,
		func() any { return &PushSubscription{} } ,
		func( _ []byte , item any ) bool {
			subscription := item.( *PushSubscription )
			if subscription.UserID == user_id { result = append( result , subscription ) }
			return true
		} )
	return
}

// DeletePushSubscription forgets a device, and whatever was waiting for it.
func DeletePushSubscription( store *db.Store , subscription_id string ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		if tx_err = tx.Delete( db.BucketPushSubscriptions , []byte( subscription_id ) ); tx_err != nil { return }
		_ , tx_err = tx.DeleteWhere( db.BucketPushDeliveries ,
			func() any { return &PushDelivery{} } ,
			func( _ []byte , item any ) bool { return item.( *PushDelivery ).SubscriptionID == subscription_id } )
		return
	} )
	return
}

// deletePushSubscriptionsTx removes every device a person has.
func deletePushSubscriptionsTx( tx *db.Tx , user_id uint64 ) ( err error ) {
	if _ , err = tx.DeleteWhere( db.BucketPushSubscriptions ,
		func() any { return &PushSubscription{} } ,
		func( _ []byte , item any ) bool { return item.( *PushSubscription ).UserID == user_id } ); err != nil { return }
	_ , err = tx.DeleteWhere( db.BucketPushDeliveries ,
		func() any { return &PushDelivery{} } ,
		func( _ []byte , item any ) bool { return item.( *PushDelivery ).UserID == user_id } )
	return
}
