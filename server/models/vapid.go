package models

import (
	errors "errors"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// vapidKeysID is the one row in BucketPushKeys.
var vapidKeysID = []byte( "vapid" )

// VAPIDKeys is the pair this server signs push requests with. Every browser's
// subscription is tied to the public half, so losing or replacing the pair
// means every phone has to subscribe again. The private half is sealed on its
// own with the secret key, like a TOTP secret, so it stays sealed with
// encrypt_at_rest off. It lives in its own bucket because RekeyRecord has to
// find it: see rekeyFields.
type VAPIDKeys struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// LoadVAPIDKeys returns the key pair with the private half opened, generating
// it the first time. The check and the write share a transaction, so two
// first requests cannot end up with different keys.
func LoadVAPIDKeys( store *db.Store , secret_key string ) ( public_key string , private_key string , err error ) {
	stored := &VAPIDKeys{}
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		tx_err = tx.Get( db.BucketPushKeys , vapidKeysID , stored )
		if errors.Is( tx_err , db.ErrNotFound ) == false { return }

		generated_public , generated_private , generate_err := encryption.VAPIDGenerateKeyPair()
		if generate_err != nil {
			tx_err = generate_err
			return
		}
		sealed , seal_err := encryption.ChaChaEncryptString( secret_key , generated_private )
		if seal_err != nil {
			tx_err = seal_err
			return
		}
		stored = &VAPIDKeys{ PublicKey: generated_public , PrivateKey: sealed }
		tx_err = tx.Put( db.BucketPushKeys , vapidKeysID , stored )
		return
	} )
	if err != nil { return }

	private_key , err = encryption.ChaChaDecryptBase64String( secret_key , stored.PrivateKey )
	if err != nil { return }
	public_key = stored.PublicKey
	return
}
