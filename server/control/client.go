package control

import (
	bytes "bytes"
	context "context"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	io "io"
	net "net"
	http "net/http"
	time "time"

	backup "ipb/server/backup"
	config "ipb/server/config"
	models "ipb/server/models"
)

// backupTimeout bounds a backup, which unlike every other call here takes as
// long as the data is big. A local server that has said nothing for this long
// is not going to.
const backupTimeout = 30 * time.Minute

// ErrNoServer means nothing is listening on the control socket, which is the
// normal state on a fresh install or with the server stopped. Callers treat
// it as "fall back to opening the database directly" rather than as failure.
var ErrNoServer = errors.New( "control: no server is listening" )

// Client talks to a running server over the control socket. The host in the
// URL is a placeholder -- the transport ignores it and dials the socket path
// instead -- but net/http still requires one to be present.
type Client struct {
	http *http.Client
	// long is the same connection without the short deadline, for the one
	// call that takes as long as the data is big.
	long *http.Client
	path string
}

// Dial connects to the control socket, returning ErrNoServer if no server
// holds it. It performs a real request rather than only opening the socket,
// so a socket file left behind by a killed process is reported as absent
// instead of appearing live and then hanging on first use.
func Dial( cfg *config.Config ) ( client *Client , err error ) {
	if cfg.ControlSocketEnabled == false {
		err = ErrNoServer
		return
	}

	socket_path := cfg.ControlSocketPath
	// Same limit the listener checks. Dialing an over-long path fails with
	// the same unhelpful error, and here it simply means no server.
	if len( socket_path ) > maxSocketPathLength {
		err = ErrNoServer
		return
	}
	candidate := &Client{
		path: socket_path,
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func( ctx context.Context , network string , address string ) ( conn net.Conn , dial_err error ) {
					dialer := net.Dialer{}
					conn , dial_err = dialer.DialContext( ctx , "unix" , socket_path )
					return
				},
			},
		},
	}

	candidate.long = &http.Client{ Timeout: backupTimeout , Transport: candidate.http.Transport }

	if _ , health_err := candidate.Health(); health_err != nil {
		err = ErrNoServer
		return
	}
	client = candidate
	return
}

// Close releases the transport's idle connections. The socket itself belongs
// to the server process, so there is nothing here to unlink.
func ( client *Client ) Close() ( err error ) {
	if client == nil {
		return
	}
	client.http.CloseIdleConnections()
	return
}

// Path reports the socket this client is bound to, so a caller can say where
// it sent a command.
func ( client *Client ) Path() ( result string ) {
	result = client.path
	return
}

// errorBody is the shape every control error response uses.
type errorBody struct {
	Error string `json:"error"`
}

// do performs one request and decodes the response into out. A non-2xx status
// is turned into the server's own error message, so the CLI reports the same
// wording the server used rather than a bare status code.
func ( client *Client ) do( method string , path string , body any , out any ) ( err error ) {
	err = client.send( client.http , method , path , body , out )
	return
}

func ( client *Client ) send( caller *http.Client , method string , path string , body any , out any ) ( err error ) {
	var payload io.Reader
	if body != nil {
		encoded , encode_err := json.Marshal( body )
		if encode_err != nil {
			err = encode_err
			return
		}
		payload = bytes.NewReader( encoded )
	}

	request , err := http.NewRequest( method , "http://control"+path , payload )
	if err != nil { return }
	if body != nil {
		request.Header.Set( "Content-Type" , "application/json" )
	}

	response , err := caller.Do( request )
	if err != nil { return }
	defer response.Body.Close()

	raw , err := io.ReadAll( io.LimitReader( response.Body , maxRequestBytes ) )
	if err != nil { return }

	if response.StatusCode < 200 || response.StatusCode > 299 {
		failure := errorBody{}
		if json.Unmarshal( raw , &failure ) == nil && failure.Error != "" {
			err = errors.New( failure.Error )
			return
		}
		err = fmt.Errorf( "control server returned %s" , response.Status )
		return
	}

	if out != nil {
		err = json.Unmarshal( raw , out )
	}
	return
}

// Backup asks the server to write a backup, and waits for it.
func ( client *Client ) Backup( options backup.Options ) ( result backup.Result , err error ) {
	request := BackupRequest{ Out: options.Out , IncludeKey: options.IncludeKey }
	err = client.send( client.long , http.MethodPost , "/v1/backup" , request , &result )
	return
}

func ( client *Client ) Health() ( health HealthResponse , err error ) {
	err = client.do( http.MethodGet , "/v1/health" , nil , &health )
	return
}

func ( client *Client ) ListUsers() ( users []UserResponse , err error ) {
	users = []UserResponse{}
	err = client.do( http.MethodGet , "/v1/users" , nil , &users )
	return
}

func ( client *Client ) CreateUser( display_name string , role string ) ( user UserResponse , err error ) {
	err = client.do( http.MethodPost , "/v1/users" ,
		CreateUserRequest{ DisplayName: display_name , Role: role } , &user )
	return
}

func ( client *Client ) ReissueLogin( user_id uint64 ) ( user UserResponse , err error ) {
	err = client.do( http.MethodPost , fmt.Sprintf( "/v1/users/%d/login-token" , user_id ) , nil , &user )
	return
}

func ( client *Client ) SetDisabled( user_id uint64 , disabled bool ) ( user UserResponse , err error ) {
	err = client.do( http.MethodPost , fmt.Sprintf( "/v1/users/%d/disabled" , user_id ) ,
		SetDisabledRequest{ Disabled: disabled } , &user )
	return
}

func ( client *Client ) RevokeAccess( user_id uint64 ) ( revoked models.Revoked , err error ) {
	err = client.do( http.MethodPost , fmt.Sprintf( "/v1/users/%d/revoke-access" , user_id ) , nil , &revoked )
	return
}

func ( client *Client ) ResetTwoFactor( user_id uint64 ) ( err error ) {
	err = client.do( http.MethodPost , fmt.Sprintf( "/v1/users/%d/reset-two-factor" , user_id ) , nil , nil )
	return
}

// ListAPIKeys returns every key, or one user's when user_id is non-zero.
func ( client *Client ) ListAPIKeys( user_id uint64 ) ( keys []APIKeyResponse , err error ) {
	keys = []APIKeyResponse{}
	path := "/v1/api-keys"
	if user_id != 0 {
		path = fmt.Sprintf( "%s?user_id=%d" , path , user_id )
	}
	err = client.do( http.MethodGet , path , nil , &keys )
	return
}

// CreateAPIKey mints a key for a user. The response carries the credential,
// which is the only time it exists outside the caller that asked for it.
func ( client *Client ) CreateAPIKey( user_id uint64 , name string , role string , expires_in_days *int ) ( key APIKeyResponse , err error ) {
	err = client.do( http.MethodPost , "/v1/api-keys" ,
		CreateAPIKeyRequest{ UserID: user_id , Name: name , Role: role , ExpiresInDays: expires_in_days } , &key )
	return
}

func ( client *Client ) RevokeAPIKey( key_id string ) ( key APIKeyResponse , err error ) {
	err = client.do( http.MethodPost , fmt.Sprintf( "/v1/api-keys/%s/revoke" , key_id ) , nil , &key )
	return
}

// CreateInviteLink makes an invite link as the admin user_id. The response
// carries the credential, the only time it exists.
func ( client *Client ) CreateInviteLink( user_id uint64 , label string , max_uses int , days int ) ( link InviteLinkResponse , err error ) {
	err = client.do( http.MethodPost , "/v1/invite-links" ,
		CreateInviteLinkRequest{ UserID: user_id , Label: label , MaxUses: max_uses , Days: days } , &link )
	return
}

// DeleteAPIKey returns the key as it was just before it was removed.
func ( client *Client ) DeleteAPIKey( key_id string ) ( key APIKeyResponse , err error ) {
	err = client.do( http.MethodPost , fmt.Sprintf( "/v1/api-keys/%s/delete" , key_id ) , nil , &key )
	return
}

func ( client *Client ) DeleteUser( user_id uint64 ) ( removed models.Revoked , err error ) {
	err = client.do( http.MethodPost , fmt.Sprintf( "/v1/users/%d/delete" , user_id ) , nil , &removed )
	return
}

func ( client *Client ) TransferOwner( user_id uint64 ) ( user UserResponse , err error ) {
	err = client.do( http.MethodPost , "/v1/owner" , TransferOwnerRequest{ UserID: user_id } , &user )
	return
}
