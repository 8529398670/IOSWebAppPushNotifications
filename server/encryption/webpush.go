package encryption

import (
	aes "crypto/aes"
	cipher "crypto/cipher"
	ecdh "crypto/ecdh"
	ecdsa "crypto/ecdsa"
	elliptic "crypto/elliptic"
	hkdf "crypto/hkdf"
	random "crypto/rand"
	sha256 "crypto/sha256"
	base64 "encoding/base64"
	binary "encoding/binary"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	time "time"
)

// Web Push, both halves of it: RFC 8291 seals a message so only the browser
// that subscribed can read it, and RFC 8292 (VAPID) proves to the push service
// that this server is the one that browser subscribed to. Keys travel as
// unpadded base64url, the form browsers hand them over in.

const (
	// webPushRecordSize is the record size written into the aes128gcm header.
	// One record holds a whole message, since a push payload is under 4KB.
	webPushRecordSize = 4096
	webPushSaltLength = 16
	webPushPublicKeyLength = 65
	webPushAuthLength = 16
	// webPushLastRecord is the padding delimiter that ends the final record.
	webPushLastRecord = 0x02
	// WebPushMaxPlainText is the most a sealed message can carry: the 4096
	// bytes push services accept, less the 86 byte header, the delimiter and
	// the 16 byte tag.
	WebPushMaxPlainText = 3993
)

var (
	ErrWebPushKey     = errors.New( "the subscription's encryption keys are not valid" )
	ErrWebPushTooLong = errors.New( "the push message is too long" )
)

func webPushDecode( value string ) ( result []byte , err error ) {
	result , err = base64.RawURLEncoding.DecodeString( value )
	return
}

func webPushEncode( value []byte ) ( result string ) {
	result = base64.RawURLEncoding.EncodeToString( value )
	return
}

// VAPIDGenerateKeyPair makes the P-256 pair this server signs with. Browsers
// tie each subscription to the public half, so replacing the pair ends every
// subscription there is.
func VAPIDGenerateKeyPair() ( public_key string , private_key string , err error ) {
	key , err := ecdh.P256().GenerateKey( random.Reader )
	if err != nil { return }
	public_key = webPushEncode( key.PublicKey().Bytes() )
	private_key = webPushEncode( key.Bytes() )
	return
}

// VAPIDAuthorization builds the Authorization header for one request to a push
// service. audience is the origin of the subscription's endpoint, and subject
// is a mailto: or https: address the service can reach the operator at.
func VAPIDAuthorization( public_key string , private_key string , audience string , subject string , expires time.Time ) ( header string , err error ) {
	raw_private , err := webPushDecode( private_key )
	if err != nil { return }
	signer , err := ecdsa.ParseRawPrivateKey( elliptic.P256() , raw_private )
	if err != nil { return }

	header_json , err := json.Marshal( map[string]string{ "typ": "JWT" , "alg": "ES256" } )
	if err != nil { return }
	claims_json , err := json.Marshal( map[string]any{
		"aud": audience,
		"exp": expires.Unix(),
		"sub": subject,
	} )
	if err != nil { return }

	unsigned := webPushEncode( header_json ) + "." + webPushEncode( claims_json )
	digest := sha256.Sum256( []byte( unsigned ) )
	r , s , err := ecdsa.Sign( random.Reader , signer , digest[ : ] )
	if err != nil { return }

	// JWS wants r and s as two fixed 32 byte halves, not ASN.1.
	signature := make( []byte , 64 )
	r.FillBytes( signature[ :32 ] )
	s.FillBytes( signature[ 32: ] )

	header = fmt.Sprintf( "vapid t=%s.%s, k=%s" , unsigned , webPushEncode( signature ) , public_key )
	return
}

// WebPushEncrypt seals plain_text for one subscription, as the aes128gcm body
// of the request to its push service. p256dh and auth are the keys the browser
// gave when it subscribed.
func WebPushEncrypt( plain_text []byte , p256dh string , auth string ) ( body []byte , err error ) {
	ephemeral , err := ecdh.P256().GenerateKey( random.Reader )
	if err != nil { return }
	salt := GenerateRandomBytes( webPushSaltLength )
	body , err = webPushSeal( plain_text , p256dh , auth , ephemeral , salt )
	return
}

// webPushSeal is WebPushEncrypt with the random parts passed in, which is what
// lets the test reproduce the RFC's worked example byte for byte.
func webPushSeal( plain_text []byte , p256dh string , auth string , ephemeral *ecdh.PrivateKey , salt []byte ) ( body []byte , err error ) {
	if len( plain_text ) > WebPushMaxPlainText {
		err = ErrWebPushTooLong
		return
	}
	browser_public_bytes , err := webPushDecode( p256dh )
	if err != nil || len( browser_public_bytes ) != webPushPublicKeyLength {
		err = ErrWebPushKey
		return
	}
	auth_secret , err := webPushDecode( auth )
	if err != nil || len( auth_secret ) != webPushAuthLength {
		err = ErrWebPushKey
		return
	}
	browser_public , err := ecdh.P256().NewPublicKey( browser_public_bytes )
	if err != nil {
		err = ErrWebPushKey
		return
	}
	shared_secret , err := ephemeral.ECDH( browser_public )
	if err != nil { return }

	server_public_bytes := ephemeral.PublicKey().Bytes()

	key_info := append( []byte( "WebPush: info\x00" ) , browser_public_bytes... )
	key_info = append( key_info , server_public_bytes... )
	input_key , err := hkdf.Key( sha256.New , shared_secret , auth_secret , string( key_info ) , 32 )
	if err != nil { return }

	content_key , err := hkdf.Key( sha256.New , input_key , salt , "Content-Encoding: aes128gcm\x00" , 16 )
	if err != nil { return }
	nonce , err := hkdf.Key( sha256.New , input_key , salt , "Content-Encoding: nonce\x00" , 12 )
	if err != nil { return }

	block , err := aes.NewCipher( content_key )
	if err != nil { return }
	sealer , err := cipher.NewGCM( block )
	if err != nil { return }

	padded := make( []byte , 0 , len( plain_text ) + 1 )
	padded = append( padded , plain_text... )
	padded = append( padded , webPushLastRecord )

	body = make( []byte , 0 , webPushSaltLength + 5 + len( server_public_bytes ) + len( padded ) + sealer.Overhead() )
	body = append( body , salt... )
	body = binary.BigEndian.AppendUint32( body , webPushRecordSize )
	body = append( body , byte( len( server_public_bytes ) ) )
	body = append( body , server_public_bytes... )
	body = sealer.Seal( body , nonce , padded , nil )
	return
}
