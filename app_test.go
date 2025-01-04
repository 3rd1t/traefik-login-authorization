package traefik_login_authorization_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	. "github.com/3rd1t/traefik_login_authorization"

	"github.com/golang-jwt/jwt/v4"
)

// TestCustomJWTAuth demonstrates how to test the plugin’s logic.
func TestCustomJWTAuth(t *testing.T) {

	//---------------------------------------------------------------------
	// 1. Setup a Mock AuthServer (server1) to test the "login" flow
	//---------------------------------------------------------------------

	// This mock server will respond with "Authenticate=true" if the form data
	// includes user=admin and pass=secret. Otherwise, it won't.
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		user := r.FormValue("username")
		pass := r.FormValue("password")

		// For demonstration: the only "valid" credential
		if user == "admin" && pass == "secret" {
			_, _ = w.Write([]byte("Authenticate=true"))
		} else {
			_, _ = w.Write([]byte("Authenticate=false"))
		}
	}))
	defer mockAuthServer.Close()

	//---------------------------------------------------------------------
	// 2. Prepare plugin config & create the plugin
	//---------------------------------------------------------------------
	cfg := &Config{
		SecretKey:                          "test-secret-key",
		TokenExpiration:                    3600,
		AuthServer:                         mockAuthServer.URL,
		AuthSuccessIndicator:               "Authenticate=true",
		AuthSuccessIndicatorComparisonType: "Contains",
		UsernamePropertyName:               "username",
		PasswordPropertyName:               "password",
		LoginMethodType:                    "Form",
		ApiKey:                             "",
		AuthFlowType:                       "LoginFlow",
		UsernameHeaderName:                 "X-Username",
		PasswordHeaderName:                 "X-Password",
		ApiKeyHeaderName:                   "X-ApiKey",
	}

	// A simple "next" handler to check if the middleware
	// actually forwards the request to "server2".
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If we arrive here, it means the JWT was valid.
		w.Header().Set("X-Forwarded", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Request forwarded to next handler"))
	})

	plugin, err := New(context.Background(), nextHandler, cfg, "test-custom-jwt")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	//---------------------------------------------------------------------
	// 3. Subtests
	//---------------------------------------------------------------------
	t.Run("LoginWithValidCredentials_ShouldReturnJWT", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Username", "admin")
		req.Header.Set("X-Password", "secret")

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", rr.Code)
			return
		}

		// Check response body for a "token"
		bodyBytes, _ := io.ReadAll(rr.Body)
		body := string(bodyBytes)
		if !strings.Contains(body, `"token":`) {
			t.Errorf("Expected a JSON response with 'token', got: %s", body)
		}
	})

	t.Run("LoginWithInvalidCredentials_ShouldReturnUnauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Username", "bad-user")
		req.Header.Set("X-Password", "bad-pass")

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", rr.Code)
		}
	})

	t.Run("NoXUsernameAndXPassword_NoBearerToken_ShouldReturnUnauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// No X-Username / X-Password
		// No Authorization header either

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", rr.Code)
		}
	})

	t.Run("ValidBearerToken_ShouldForwardRequest", func(t *testing.T) {
		// First, we need a valid token.
		tokenStr, err := generateValidToken(cfg.SecretKey, "testuser")
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", rr.Code)
			return
		}

		// Check if it was forwarded to next handler
		if rr.Header().Get("X-Forwarded") != "true" {
			t.Errorf("Expected request to be forwarded, but it wasn't.")
		}
	})

	t.Run("InvalidBearerToken_ShouldReturnUnauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+"abc.def.ghi") // obviously invalid

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", rr.Code)
		}
	})

	t.Run("NoBearerToken_ShouldReturnUnauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// No bearer token here.

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %d", rr.Code)
		}
	})
}

// generateValidToken is a helper to create a JWT using the same signing method
// as the plugin. This allows us to test the "valid token" scenario.
func generateValidToken(secretKey, username string) (string, error) {
	claims := jwt.MapClaims{
		"sub": username,
		"exp": jwt.NewNumericDate(jwt.TimeFunc().Add(
			// 1 hour
			60 * 60 * 1 * 1e9,
		)),
		"iat": jwt.NewNumericDate(jwt.TimeFunc()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}
