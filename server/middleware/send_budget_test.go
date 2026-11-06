package middleware

import (
	testing "testing"

	fiber "github.com/gofiber/fiber/v3"
)

// A spelling the router accepts must land on the same budget, or a script could
// pick one that spends the budget the app's pages live on.
func TestTheNotificationAPIHasItsOwnBudget( t *testing.T ) {
	for _ , path := range []string{ "/api/v1/messages" , "/API/V1/Messages/" , "/1/messages.json" } {
		if got := budgetFor( fiber.MethodPost , path ); got != budgetSend {
			t.Errorf( "%s: got %d" , path , got )
		}
	}
	if got := budgetFor( fiber.MethodGet , "/api/v1/messages" ); got == budgetSend {
		t.Error( "a GET is not a send" )
	}
}
