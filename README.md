# Traefik Login Authentication Plugin

A Traefik 3 middleware plugin that handles user authentication using JWT tokens. This plugin intercepts incoming requests, validates user credentials against an external authentication server, generates JWT tokens upon successful authentication, and protects downstream services by verifying JWT tokens on subsequent requests.


Configuration
---
Configure the plugin via Traefik's dynamic configuration using YAML or Docker labels. The main configurable parameters include:

Plugin Properties
---
Property | Type	| Description |	Default Value
-|-|-|-
secretKey |	string |	Secret key used to sign and verify JWT tokens. |	Required
tokenExpiration |	int64 |	Duration in seconds before the JWT expires. |	3600 (1 hour)
authServer |	string |	URL of the external authentication server to validate credentials. |	Required
authSuccessIndicator |	string |	String to identify successful authentication in the auth server's response. |	""
authSuccessIndicatorComparisonType |	string |	Type of comparison for authSuccessIndicator (Contains, Equals, NotEquals, NotContains). |	"Contains"
usernamePropertyName |	string |	Property name used in the Form request to authServer. Its value is extracted from X-Username header |	"username"
passwordPropertyName |	string |	Property name used in the Form request to authServer. Its value extracted from X-Password header |	"password"
authFlowType | string | Use LoginFlow or use ApiKeyAndLoginFlow to check the ApiKey before the login. Use ApiKeyFlow to bypass the login flow and to check only the ApiKey | "LoginFlow"
apiKey |	string |	Direct access without login through X-ApiKey header |	Optional
loginMethodType | string | Json for application/json or Form for application/x-www-form-urlencoded request | Json
usernameHeaderName | string | Username header name | X-Username
passwordHeaderName | string | Password header name | X-Password
apiKeyHeaderName | string | ApiKey header name | X-ApiKey

Login Flow
---

## First Request (Login)

### Headers

```
X-Username: <USERNAME>
X-Password: <PASSWORD>
```

The plugin sends a application/x-www-form-urlencoded or application/json POST request to the configured authServer with the provided credentials.
If the response meets the authSuccessIndicator criteria based on authSuccessIndicatorComparisonType, a JWT token is generated and returned to the client in JSON format.

Subsequent Requests (Authenticated Access)
---

### Headers

```
Authorization: Bearer <JWT_TOKEN>
```

The plugin verifies the JWT token.
If valid, the request is forwarded to the downstream service (server2).
If invalid or missing, a 401 Unauthorized response is returned.


ApiKey Flow
---

### Headers

```
X-ApiKey: <APIKEY>
```

The plugin checks the ApiKey against the apiKey parameter.
If the check is successful the request is forwarded to the downstream service.

ApiKey+Login Flow
---

Combination of the two flows

Configure Traefik to Use the Plugin
---

Update your Traefik static configuration to recognize the plugin.
```yml
# traefik.yml
experimental:
  plugins:
    login-authorization:
      moduleName: "github.com/3rd1t/traefik_login_authorization"
      version: "v0.0.1"
```

Example dynamic.yaml
---
```yml
http:
  routers:
    my-router:
      rule: "Host(`example.com`)"
      entryPoints:
        - web
      service: my-service
      middlewares:
        - my-plugin-middleware

  services:
    my-service:
      loadBalancer:
        servers:
          - url: "http://server2:8080"  # The target for valid JWT requests

  middlewares:
    my-plugin-middleware:
      plugin:
        login-authorization:
          authServer: "https://dummyjson.com/auth/login"
          secretKey: "my-super-secret-key"
          tokenExpiration: 2592000
          authSuccessIndicator: "\"accessToken\""
          usernamePropertyName: "username"
          passwordPropertyName: "password"
          loginMethodType: "Json"
          authFlowType: "LoginFlow"
```

Docker Labels Example
---

```
labels:
  - "traefik.http.routers.my-router.rule=Host(`example.com`)"
  - "traefik.http.routers.my-router.entrypoints=web"
  - "traefik.http.routers.my-router.middlewares=my-plugin-middleware"
  - "traefik.http.services.my-service.loadbalancer.server.port=8080"

  - "traefik.http.middlewares.my-plugin-middleware.plugin.login-authorization.authServer=https://dummyjson.com/auth/login"
  - "traefik.http.middlewares.my-plugin-middleware.plugin.login-authorization.secretKey=my-super-secret-key"
  - "traefik.http.middlewares.my-plugin-middleware.plugin.login-authorization.tokenExpiration=3600"
  - "traefik.http.middlewares.my-plugin-middleware.plugin.login-authorization.authSuccessIndicator=\"accessToken\""
  - "traefik.http.middlewares.my-plugin-middleware.plugin.login-authorization.usernamePropertyName=username"
  - "traefik.http.middlewares.my-plugin-middleware.plugin.login-authorization.passwordPropertyName=password"
  - "traefik.http.middlewares.my-plugin-middleware.plugin.login-authorization.loginMethodType=Json"
  - "traefik.http.middlewares.my-plugin-middleware.plugin.login-authorization.authFlowType=LoginFlow"
```
