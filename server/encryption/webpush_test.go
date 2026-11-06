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
	big "math/big"
	strings "strings"
	testing "testing"
	time "time"
)

// The worked example in RFC 8291, Appendix A.
const (
	rfcPlainText  = "When I grow up, I want to be a watermelon"
	rfcAuth       = "BTBZMqHH6r4Tts7J_aSIgg"
	rfcSalt       = "DGv6ra1nlYgDCS1FRnbzlw"
	rfcServerKey  = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	rfcBrowserPub = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rfcBody       = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
)

func TestWebPushMatchesTheRFC( t *testing.T ) {
	server_key_bytes , err := webPushDecode( rfcServerKey )
	if err != nil { t.Fatal( err ) }
	server_key , err := ecdh.P256().NewPrivateKey( server_key_bytes )
	if err != nil { t.Fatal( err ) }
	salt , err := webPushDecode( rfcSalt )
	if err != nil { t.Fatal( err ) }

	body , err := webPushSeal( []byte( rfcPlainText ) , rfcBrowserPub , rfcAuth , server_key , salt )
	if err != nil { t.Fatal( err ) }
	if got := webPushEncode( body ); got != rfcBody {
		t.Fatalf( "sealed body differs from RFC 8291\n got %s\nwant %s" , got , rfcBody )
	}
}

// open is the browser's side of RFC 8291, so a round trip proves more than the
// one fixed example does.
func open( t *testing.T , body []byte , browser *ecdh.PrivateKey , auth []byte ) ( plain []byte ) {
	t.Helper()
	salt := body[ :16 ]
	key_length := int( body[ 20 ] )
	server_public_bytes := body[ 21 : 21 + key_length ]
	sealed := body[ 21 + key_length: ]

	server_public , err := ecdh.P256().NewPublicKey( server_public_bytes )
	if err != nil { t.Fatal( err ) }
	shared , err := browser.ECDH( server_public )
	if err != nil { t.Fatal( err ) }

	info := append( []byte( "WebPush: info\x00" ) , browser.PublicKey().Bytes()... )
	info = append( info , server_public_bytes... )
	input_key , err := hkdf.Key( sha256.New , shared , auth , string( info ) , 32 )
	if err != nil { t.Fatal( err ) }
	content_key , err := hkdf.Key( sha256.New , input_key , salt , "Content-Encoding: aes128gcm\x00" , 16 )
	if err != nil { t.Fatal( err ) }
	nonce , err := hkdf.Key( sha256.New , input_key , salt , "Content-Encoding: nonce\x00" , 12 )
	if err != nil { t.Fatal( err ) }

	block , err := aes.NewCipher( content_key )
	if err != nil { t.Fatal( err ) }
	opener , err := cipher.NewGCM( block )
	if err != nil { t.Fatal( err ) }
	padded , err := opener.Open( nil , nonce , sealed , nil )
	if err != nil { t.Fatal( err ) }
	if padded[ len( padded ) - 1 ] != webPushLastRecord {
		t.Fatalf( "last byte %x is not the final record delimiter" , padded[ len( padded ) - 1 ] )
	}
	plain = padded[ : len( padded ) - 1 ]
	return
}

func TestWebPushRoundTripAtTheSizeLimit( t *testing.T ) {
	browser , err := ecdh.P256().GenerateKey( random.Reader )
	if err != nil { t.Fatal( err ) }
	auth := GenerateRandomBytes( 16 )
	message := strings.Repeat( "x" , WebPushMaxPlainText )

	body , err := WebPushEncrypt( []byte( message ) , webPushEncode( browser.PublicKey().Bytes() ) , webPushEncode( auth ) )
	if err != nil { t.Fatal( err ) }
	if len( body ) > 4096 {
		t.Fatalf( "body is %d bytes, over what push services accept" , len( body ) )
	}
	if got := open( t , body , browser , auth ); string( got ) != message {
		t.Fatal( "the round trip changed the message" )
	}

	_ , err = WebPushEncrypt( []byte( message + "x" ) , webPushEncode( browser.PublicKey().Bytes() ) , webPushEncode( auth ) )
	if err != ErrWebPushTooLong {
		t.Fatalf( "over the limit: got %v" , err )
	}
}

func TestWebPushRefusesBadKeys( t *testing.T ) {
	cases := map[string][2]string{
		"not base64":      { "!!!" , rfcAuth },
		"short key":       { "BCVx" , rfcAuth },
		"off the curve":   { "B" + strings.Repeat( "A" , 86 ) , rfcAuth },
		"short auth":      { rfcBrowserPub , "BTBZ" },
	}
	for name , keys := range cases {
		if _ , err := WebPushEncrypt( []byte( "hi" ) , keys[ 0 ] , keys[ 1 ] ); err != ErrWebPushKey {
			t.Fatalf( "%s: got %v" , name , err )
		}
	}
}

func TestVAPIDSignatureVerifies( t *testing.T ) {
	public_key , private_key , err := VAPIDGenerateKeyPair()
	if err != nil { t.Fatal( err ) }

	expires := time.Now().Add( time.Hour )
	header , err := VAPIDAuthorization( public_key , private_key , "https://web.push.apple.com" , "mailto:a@example.com" , expires )
	if err != nil { t.Fatal( err ) }

	if strings.HasPrefix( header , "vapid t=" ) == false {
		t.Fatalf( "header %q" , header )
	}
	token , key , found := strings.Cut( strings.TrimPrefix( header , "vapid t=" ) , ", k=" )
	if found == false || key != public_key {
		t.Fatalf( "header %q does not carry the public key" , header )
	}

	parts := strings.Split( token , "." )
	if len( parts ) != 3 { t.Fatalf( "token %q" , token ) }
	claims , err := webPushDecode( parts[ 1 ] )
	if err != nil { t.Fatal( err ) }
	if strings.Contains( string( claims ) , `"aud":"https://web.push.apple.com"` ) == false {
		t.Fatalf( "claims %s" , claims )
	}

	signature , err := webPushDecode( parts[ 2 ] )
	if err != nil { t.Fatal( err ) }
	if len( signature ) != 64 { t.Fatalf( "signature is %d bytes" , len( signature ) ) }

	public_bytes , err := webPushDecode( public_key )
	if err != nil { t.Fatal( err ) }
	verifier , err := ecdsa.ParseUncompressedPublicKey( elliptic.P256() , public_bytes )
	if err != nil { t.Fatal( err ) }
	digest := sha256.Sum256( []byte( parts[ 0 ] + "." + parts[ 1 ] ) )
	r := new( big.Int ).SetBytes( signature[ :32 ] )
	s := new( big.Int ).SetBytes( signature[ 32: ] )
	if ecdsa.Verify( verifier , digest[ : ] , r , s ) == false {
		t.Fatal( "the signature does not verify against the public key" )
	}
}
