# TODO

## Authorization server

Some potential things that could be added to this auth server.

- [ ] Tidy up tests
- [ ] Add /userinfo support for opqaue access tokens
- [ ] Support client_credentials grant (incl access tokens without a subject)
- [ ] Support public clients - i.e. without client authentication.
- [ ] Refresh token rotation
- [ ] Refresh token revocation
- [ ] Support key rotation
- [ ] More OIDC checks https://openid.net/specs/openid-connect-core-1_0.html
- [ ] Support downscoping resource/audience on refresh token grants
- [ ] Ability to reduce scopes on token refresh but not increase. Remember original scopes for future refreshes.
- [ ] Token introspection https://datatracker.ietf.org/doc/html/rfc7662
- [ ] Token exchange https://datatracker.ietf.org/doc/html/rfc8693
- [ ] Dynamic client registration https://datatracker.ietf.org/doc/html/rfc7591
- [ ] Auth server session
- [ ] Make auth server state be stored server side rather than shared by query params between sign in/sign up.
- [ ] Support multiple resource indicators in a single request
- [x] Auth server filtering of scopes per provided resource
- [x] RBAC
- [x] Resource indicators https://datatracker.ietf.org/doc/html/rfc8707
- [x] Change from username to user ID
- [x] OIDC /userinfo endpoint
- [x] Move some server config to be per client
- [x] Move all token expiry to server config.
- [x] Refresh tokens static
- [x] Add `expires_in` to token response
- [x] `nonce`
- [x] OIDC - ID token
- [x] Scopes
- [x] PKCE https://datatracker.ietf.org/doc/html/rfc7636
- [x] Allow sign up
- [x] Allow multiple users
- [x] User sign in
- [x] JWT access token https://datatracker.ietf.org/doc/html/rfc9068
- [x] `state`
- [x] Opaque access token
- [x] OAuth authorization code flow basic
- [x] Well known endpoint https://openid.net/specs/openid-connect-discovery-1_0.html

## Client

- [ ] Session to remember state/tokens
- [ ] Look at https://datatracker.ietf.org/doc/html/rfc9068 JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
- [ ] Add client credentials flow
- [ ] Maybe other flows?
- [x] Call to protected resource with access token
- [x] Use refresh tokens

## Resource server

- [ ] Make sure JWKS cache expires properly.
- [x] Validate `aud` (audience) claim on incoming access tokens for `/orders`.
