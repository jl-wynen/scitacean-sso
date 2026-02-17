# PKCE auth with Python and Keycloak

## Standard flow

The native app needs a public client (here called `pkce`) without a client secret.
SciCat's web login needs a confidential client (here called `scicat-confidential`) with a client secret.
The native app authenticates with `pkce` and gets a token.
With the extra config, the token includes the client id as its audience (`aud = 'pkce'`).
SciCat then checks the token using a client that is also configured to use `client_id="pkce"` which maps onto the `azp` claim of the token. (This is currently not in the repo, I had to locally modify the code and hard-coded that client id.)
This setup seems to work :-)

## Device flow

The standard flow with a local redirect does not work on Jupyter Hub because the `localhost` used by the browser is not the same as the one used by the Python kernel.
Plus, `webbrowser` cannot open tabs in this case.
The device flow is a little less user friendly but should work in that setup.

The native app requests a device code from the IdP and tells the user to open a URL and it provides a code to the user to enter in that URL (or encodes the code in the URL directly).
Meanwhile, the app repeatedly queries the IdP while login is pending.
Once the user authorizes the app, the app receives an access token.

For testing purposes, there is a dedicated client for the device flow so we can neatly separate the two flows.
But that is not required in production, we just need a public client with the correct flows.
All the same audience and issuer requirements apply.

## Networking

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
    - Included Client Audience: pkce

### Device client

1. In the [admin console](http://localhost:8080/admin), open the 'Clients' page.
2. Create a new client with
  - General:
    - Client type: OpenID Connect
    - Client ID: device
    - [Other fields are optional]
  - Cabability:
    - Client authentication: Off
    - Authentication flow: OAuth 2.0 Device Authorization Grant
    - PKCE method: Leave blank (The client will send the code challenge and exchange method)
  - Login settings:
    - Leave blank
4. Under 'Client scopes', add the predefined 'device-dedicated' scope.
   (See https://www.keycloak.org/docs/latest/server_admin/#_audience_hardcoded)
   - In that scope, add a new mapper:
    - Type: Audience
    - Name: SciCat backend
    - Included Client Audience: device

### Networking

Add `127.0.0.1 keycloak.local` to `/etc/hosts`.

## Notes

- Keycloak auth endpoints are listed at http://localhost:8080/realms/pkce-test/.well-known/openid-configuration
