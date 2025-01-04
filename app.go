package traefik_login_authorization

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// ----------------------------------------------------------------------------
// 1) Configuration
// ----------------------------------------------------------------------------

// Config is the plugin configuration structure.
type Config struct {
	SecretKey                          string `json:"secretKey,omitempty"`            // SecretKey is the secret key used to sign JWT tokens.
	TokenExpiration                    int64  `json:"tokenExpiration,omitempty"`      // TokenExpiration is the duration (in seconds) before the JWT expires.
	AuthServer                         string `json:"authServer,omitempty"`           // AuthServer is the endpoint on server1 that checks if Authenticate=true based on user/password.
	AuthSuccessIndicator               string `json:"authSuccessIndicator,omitempty"` // AuthSuccessIndicator is the string that we expect to find in the response from AuthServer to indicate success.
	AuthSuccessIndicatorComparisonType string `json:"authSuccessIndicatorComparisonType,omitempty"`
	UsernamePropertyName               string `json:"usernamePropertyName,omitempty"`
	PasswordPropertyName               string `json:"passwordPropertyName,omitempty"`
	LoginMethodType                    string `json:"loginMethodType,omitempty"`
	ApiKey                             string `json:"apiKey,omitempty"`
	AuthFlowType                       string `json:"authFlowType,omitempty"`
	UsernameHeaderName                 string `json:"usernameHeaderName,omitempty"`
	PasswordHeaderName                 string `json:"passwordHeaderName,omitempty"`
	ApiKeyHeaderName                   string `json:"apiKeyHeaderName,omitempty"`
}

// CreateConfig instantiates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		SecretKey:                          "",
		TokenExpiration:                    3600, // 1 hour default
		AuthServer:                         "",
		AuthSuccessIndicator:               "",
		AuthSuccessIndicatorComparisonType: "Contains", // or Equals or NotEquals or NotContains
		UsernamePropertyName:               "username",
		PasswordPropertyName:               "password",
		LoginMethodType:                    "Json", // or Form
		ApiKey:                             "",
		AuthFlowType:                       "LoginFlow", // or ApiKeyFlow or ApiKeyAndLoginFlow
		UsernameHeaderName:                 "X-Username",
		PasswordHeaderName:                 "X-Password",
		ApiKeyHeaderName:                   "X-ApiKey",
	}
}

// ----------------------------------------------------------------------------
// 2) Constructor
// ----------------------------------------------------------------------------

type CustomJWTAuth struct {
	next   http.Handler
	name   string
	config *Config
}

// New creates a new CustomJWTAuth middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if (config.AuthFlowType == "ApiKeyAndLoginFlow" || config.AuthFlowType == "ApiKeyFlow") && len(config.ApiKey) == 0 {
		return nil, errors.New("api key cannot be empty if auth type is ApiKeyAndLoginFlow or ApiKeyFlow")
	}

	if (config.AuthFlowType == "ApiKeyAndLoginFlow" || config.AuthFlowType == "LoginFlow") && len(config.AuthServer) == 0 {
		return nil, errors.New("auth server cannot be empty if auth type is ApiKeyAndLoginFlow or LoginFlow")
	}

	if len(config.AuthServer) > 0 {
		if len(config.SecretKey) == 0 {
			return nil, errors.New("secret key cannot be empty if auth type is ApiKeyAndLoginFlow or LoginFlow")
		}
		if config.LoginMethodType != "Json" && config.LoginMethodType != "Form" {
			return nil, errors.New("login method type must be Json or Form if auth type is ApiKeyAndLoginFlow or LoginFlow")
		}
		if len(config.UsernamePropertyName) == 0 || len(config.PasswordPropertyName) == 0 {
			return nil, errors.New("username and password properties cannot be empty if auth type is ApiKeyAndLoginFlow or LoginFlow")
		}
	}

	if len(config.AuthSuccessIndicator) == 0 {
		return nil, errors.New("authSuccessIndicator cannot be empty")
	}

	return &CustomJWTAuth{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

// ----------------------------------------------------------------------------
// 3) Main Handler Logic
// ----------------------------------------------------------------------------

// ServeHTTP implements the http.Handler interface.
func (c *CustomJWTAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if c.config.AuthFlowType == "ApiKeyAndLoginFlow" || c.config.AuthFlowType == "ApiKeyFlow" {
		// 3.1: Check if request has X-ApiKey
		apiKey := r.Header.Get(c.config.ApiKeyHeaderName)

		if apiKey == c.config.ApiKey {
			if c.config.AuthFlowType == "ApiKey" {
				// If valid, forward the request to the next handler (e.g., server2).
				c.next.ServeHTTP(w, r)
				return
			}
		} else {
			http.Error(w, "Unauthorized - Invalid ApiKey", http.StatusUnauthorized)
			return
		}
	}

	// 3.2: Check if request has X-Username and X-Password
	username := r.Header.Get(c.config.UsernameHeaderName)
	password := r.Header.Get(c.config.PasswordHeaderName)

	// If both are present, assume this is a "login" attempt.
	if username != "" && password != "" {
		c.handleLogin(w, r, username, password)
		return
	}

	// 3.3: Otherwise, we expect a JWT token in the Authorization header.
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized - Missing Bearer token", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	valid, err := c.validateToken(tokenString)
	if err != nil || !valid {
		http.Error(w, "Unauthorized - Invalid Token", http.StatusUnauthorized)
		return
	}

	// If valid, forward the request to the next handler (e.g., server2).
	c.next.ServeHTTP(w, r)
}

// ----------------------------------------------------------------------------
// 4) Handle "Login" Step
// ----------------------------------------------------------------------------

func (c *CustomJWTAuth) handleLogin(w http.ResponseWriter, _ *http.Request, user, pass string) {
	req, err := c.createRequest(user, pass)
	if err != nil {
		http.Error(w, "Failed to create request to AuthServer", http.StatusInternalServerError)
		return
	}

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to contact AuthServer", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	if c.config.AuthSuccessIndicatorComparisonType == "Equals" {
		if !(bodyString == c.config.AuthSuccessIndicator) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
	}
	if c.config.AuthSuccessIndicatorComparisonType == "Contains" {
		if !strings.Contains(bodyString, c.config.AuthSuccessIndicator) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
	}
	if c.config.AuthSuccessIndicatorComparisonType == "NotEquals" {
		if bodyString == c.config.AuthSuccessIndicator {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
	}
	if c.config.AuthSuccessIndicatorComparisonType == "NotContains" {
		if strings.Contains(bodyString, c.config.AuthSuccessIndicator) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
	}

	// 4.1: If credentials are good, generate a JWT token and return it in JSON
	tokenString, err := c.generateToken(user)
	if err != nil {
		http.Error(w, "Could not generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"token":"%s"}`, tokenString)))
}

func (c *CustomJWTAuth) createRequest(user, pass string) (*http.Request, error) {
	if c.config.LoginMethodType == "Form" {
		// Make a POST x-www-form-urlencoded request to c.config.AuthServer
		form := url.Values{}
		form.Set(c.config.UsernamePropertyName, user)
		form.Set(c.config.PasswordPropertyName, pass)

		req, err := http.NewRequest(http.MethodPost, c.config.AuthServer, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	} else if c.config.LoginMethodType == "Json" {
		var jsonStr = []byte(fmt.Sprintf(`{"%s": "%s", "%s": "%s"}`, c.config.UsernamePropertyName, user, c.config.PasswordPropertyName, pass))
		req, err := http.NewRequest(http.MethodPost, c.config.AuthServer, bytes.NewBuffer(jsonStr))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	} else {
		return nil, fmt.Errorf("login method type must be Json or Form")
	}
}

// ----------------------------------------------------------------------------
// 5) JWT Generation & Validation
// ----------------------------------------------------------------------------

func (c *CustomJWTAuth) generateToken(username string) (string, error) {
	// Example standard claims; adapt to your needs.
	claims := jwt.MapClaims{
		"sub": username,
		"exp": time.Now().Add(time.Duration(c.config.TokenExpiration) * time.Second).Unix(),
		"iat": time.Now().Unix(),
	}

	// Create the token using the HMAC signing method.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(c.config.SecretKey))
}

func (c *CustomJWTAuth) validateToken(tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// Validate the signing algorithm
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(c.config.SecretKey), nil
	})

	if err != nil {
		return false, err
	}

	return token.Valid, nil
}
