# PKCE auth with Python and Keycloak

## Nest steps

- Make keycloak setup persistent for convenience
- Launch scicat(+mongodb) in same docker compose
- Configure scicat to use keycloak and try to use token from ketcloak with scicat.


## Keycloak setup

### General

This is adapted from https://www.keycloak.org/getting-started/getting-started-docker

1. Start Keycloak:
```bash
docker compose -f keycloak.yaml up
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

  
## Notes

- Keycloak auth endpoints are listed at http://localhost:8080/realms/pkce-test/.well-known/openid-configuration
