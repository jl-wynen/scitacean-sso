# PKCE auth with Python and Keycloak

## How this works and doesn't (currently)

The native app needs a public client (here called `pkce`) without a client secret.
SciCat's web login needs a confidential client (here called `scicat-confidential`) with a client secret.
The native app authenticates with `pkce` and gets a token.
That token has `aud` (audience) set to `scicat-confidential` so that SciCat recognizes it.
The app then sends that token to `/auth/oidc/token` to exchange it for a SciCat token.

That last step fails because the token has `azp = 'pkce'` but SciCat expects `azp = 'scicat-confidential'`.
So SciCat needs to be configured to accept tokens from `pkce` as well as from its own confidential client.

### Networking

The keycloak URL must match between host and container.
To make this work, the docker-compose file adds a new 'keycloak.local' and `/etc/hosts` maps that to localhost.
The client app and scicat both have to go through that network instead of localhost directly.

## Keycloak setup

### General

This is adapted from https://www.keycloak.org/getting-started/getting-started-docker

1. Start Keycloak:
```bash
docker compose -f compose.yaml up
```
2. Open admin console at http://localhost:8080/admin and log in with the admin credentials:
   - Username: admin
   - Password: admin
3. Create a new realm called 'pkce-test'.
4. Create a new user
  1. Create a user with name 'python'.
  2. After creating the user, under 'Credentials', set the password:
     - Password: 'pixie'
     - Make sure the password is *not* temporary!
  3. Log in under http://localhost:8080/realms/pkce-test/account to check that the user can log in.

### Confidential client

1. In the [admin console](http://localhost:8080/admin), open the 'Clients' page.
2. Create a new client with
- General:
  - Client type: OpenID Connect
  - Client ID: scicat-confidential
  - [Other fields are optional]
- Cabability:
  - Client authentication: On
  - Authentication flow: Standard Flow

### PKCE client

1. In the [admin console](http://localhost:8080/admin), open the 'Clients' page.
2. Create a new client with
  - General:
    - Client type: OpenID Connect
    - Client ID: pkce
    - [Other fields are optional]
  - Cabability:
    - Client authentication: Off
    - Authentication flow: Standard Flow
    - PKCE method: Leave blank (The client will send the code challenge and exchange method)
  - Login settings:
    - Leave blank
3. After creating the client, under 'Settings', add '*' to the 'Valid Redirect URIs'.
   This is needed to redirect to the user's machine. (secure? -> should be because of PKCE, so only allow pkce in this client)
   - TODO: limit to URLs listed on https://www.oauth.com/oauth2-servers/oauth-native-apps/redirect-urls-for-native-apps/:
   ```
   http://127.0.0.1:[port]/ and http://::1:[port]/, and http://localhost:[port]/
   ```
   This seems to require a concrete port (range) to work. At least on Keycloak.
4. Under 'Client scopes', add the predefined 'pkce-dedicated' scope.
   (See https://www.keycloak.org/docs/latest/server_admin/#_audience_hardcoded)
   - In that scope, add a new mapper:
    - Type: Audience
    - Name: SciCat backend
    - Included Client Audience: scicat-confidential

### Networking

Add `127.0.0.1 keycloak.local` to `/etc/hosts`.

## Notes

- Keycloak auth endpoints are listed at http://localhost:8080/realms/pkce-test/.well-known/openid-configuration
