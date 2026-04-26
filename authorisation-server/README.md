# OAuth Authorization Server

An OAuth Authorization Server. Mainly implemented for testing and learning. Not for use in production.

## Run
1. From the repository root, change into this directory:
- `cd authorisation-server`
1. Set required environment variables:
- `ISSUER` - The OpenID Provider Issuer Identifier. In practice, this should be the authorization server's canonical public base URL.
1. Start the development server:
- `npm run dev`

## Test login
- Username: `user`
- Password: `password`
