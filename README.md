# OAuth Testing

This repository is for OAuth testing. It contains test implementations of an OAuth and OpenID Connect:

- [Authorization Server](./authorization-server)
- [Client](./client)
- [Resource Server](./resource-server)

## Run

Use the root dev command to boot all three servers:

```zsh
npm run dev
```

- Authorization server: http://localhost:4000/.well-known/openid-configuration
- Client: http://localhost:3000 (defaults to JWT client)
- Resource server: http://localhost:5000

### Different clients
If you want to use the opaque client, either
- Boot the opaque client on port 3001, the authorization server is configured to support it here by default.
- Change client config to this `CLIENT_ID=client-id-opaque;CLIENT_SECRET=test-client-secret` and restart `dev`.