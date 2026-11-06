package middleware

import (
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
)

// maintenanceAlways stay open in every mode: the checks that watch the server,
// the words the page needs, and everything it takes to sign in and out, which
// is how the owner gets back to the switch.
var maintenanceAlways = map[string]bool{
	"/api/health":           true,
	"/api/ready":            true,
	"/metrics":              true,
	"/api/language":         true,
	"/api/me":               true,
	"/api/logout":           true,
	"/api/login":            true,
	"/api/login/options":    true,
	"/api/login/two-factor": true,
	"/api/login/password":   true,
}

// MaintenanceAllows says whether a request gets through while server.maintenance
// is on, for anyone. The owner's exemption is the caller's to add, since this
// does not know who is asking.
//
// The path is normalised as in budgetFor, because the router ignores case and
// a trailing slash. read_only trusts a GET not to change anything, so a route
// that writes on a GET must not rely on this. Invite links stay shut in both
// modes: joining makes an account. /mcp is a POST either way, and one that
// cannot be sorted into a read or a write.
func MaintenanceAllows( mode string , method string , request_path string ) ( allowed bool ) {
	normalised := strings.ToLower( request_path )
	if len( normalised ) > 1 {
		normalised = strings.TrimRight( normalised , "/" )
	}
	switch {
	case mode == config.MaintenanceNone:
		allowed = true
	case maintenanceAlways[ normalised ]:
		allowed = true
	case normalised == "/login" || strings.HasPrefix( normalised , "/login/" ):
		allowed = true
	// A file the page loads, but not a page: /index.html is the app itself.
	case staticAsset( method , normalised ) && strings.HasSuffix( normalised , ".html" ) == false:
		allowed = true
	case mode == config.MaintenanceFull:
		allowed = false
	case normalised == "/join" || strings.HasPrefix( normalised , "/join/" ) || strings.HasPrefix( normalised , "/api/join/" ):
		allowed = false
	default:
		allowed = method == fiber.MethodGet || method == fiber.MethodHead
	}
	return
}
