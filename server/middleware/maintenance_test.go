package middleware

import (
	testing "testing"

	config "ipb/server/config"
)

func TestMaintenanceAllows( t *testing.T ) {
	none , read_only , full := config.MaintenanceNone , config.MaintenanceReadOnly , config.MaintenanceFull
	cases := []struct {
		mode    string
		method  string
		path    string
		allowed bool
	}{
		{ none , "POST" , "/api/admin/users" , true },
		{ read_only , "GET" , "/" , true },
		{ read_only , "GET" , "/api/team" , true },
		{ read_only , "POST" , "/api/account/rename" , false },
		{ read_only , "POST" , "/mcp" , false },
		{ read_only , "POST" , "/api/logs/events" , false },
		{ read_only , "GET" , "/join/abc" , false },
		{ read_only , "POST" , "/api/join/create" , false },
		{ read_only , "POST" , "/api/logout" , true },
		{ read_only , "POST" , "/api/login" , true },
		{ full , "GET" , "/" , false },
		{ full , "GET" , "/index.html" , false },
		{ full , "GET" , "/api/team" , false },
		{ full , "GET" , "/join/abc" , false },
		{ full , "POST" , "/mcp" , false },
		{ full , "GET" , "/js/app.js" , true },
		{ full , "GET" , "/api/health" , true },
		{ full , "GET" , "/api/ready" , true },
		{ full , "GET" , "/metrics" , true },
		{ full , "GET" , "/api/language" , true },
		{ full , "GET" , "/api/me" , true },
		{ full , "GET" , "/login/abc.def" , true },
		{ full , "POST" , "/api/login/two-factor" , true },
		// The router ignores case and a trailing slash: a spelling must not
		// open anything, or pass for a file.
		{ full , "GET" , "/API/TEAM/" , false },
		{ full , "GET" , "/API/ADMIN/USERS.JS" , false },
		{ read_only , "POST" , "/API/JOIN/CREATE/" , false },
		{ read_only , "GET" , "/JOIN/abc" , false },
		{ full , "GET" , "/INDEX.HTML" , false },
	}
	for _ , item := range cases {
		if got := MaintenanceAllows( item.mode , item.method , item.path ); got != item.allowed {
			t.Errorf( "%s %s %s: got %v" , item.mode , item.method , item.path , got )
		}
	}
}
