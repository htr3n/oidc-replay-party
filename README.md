# OIDC Relay Party in Golang

This is a simple implementation of [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) relay party using the [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps).

## Getting Started

### OIDC Provider Configuration

You would need to add a redirect URI `http://localhost:port` to your OIDC provider so that this program can receive the authorization code and use that to obtain an access token. The port can be optionally configured with an environment variable `OIDC_CALLBACK_PORT` or by default, `6868`. That means, if you don't set `OIDC_CALLBACK_PORT`, the redirect URI (aka the callback URI) is `http://localhost:6868`. 

### Run OIDC Authentication

Run directly the program via CLI

```sh
OIDC_PROVIDER=... OIDC_CLIENT_ID=... OIDC_CLIENT_SECRET=... go run ./main.go
```

replacing the `...` with the corresponding values.

- `OIDC_PROVIDER`: the URL of the OIDC provider
- `OIDC_CLIENT_ID`: the OIDC client ID
- `OIDC_CLIENT_SECRET`: the OIDC client secret

On a Linux system, these can be set as environment variables with

```sh
OIDC_PROVIDER='...'
OIDC_CLIENT_ID='...'
OIDC_CLIENT_SECRET='...'
export OIDC_PROVIDER OIDC_CLIENT_ID OIDC_CLIENT_SECRET
```

then you can just run with `go`

```sh
go run ./main.go
```

There is an optional  for the port to receive the authorization code from the OIDC provider. If not set, it is `6868`. 

## Technical Details

- The program will try to fetch the OIDC provider metadata at `OIDC_PROVIDER//.well-known/openid-configuration` to extract some essential information, such as the authorization endpoint and token endpoint (alongside with other information).
- Using the authorization endpoint, it creates *an authorization URL* that includes a *redirect URI* (required by OIDC spec to send back *the authorization code*). It will then open the system default Web browser with the said authorization URL and, at the same time, start a call back server listening at the aforementioned *call back port*.
- The OIDC provider would show a login screen for the user to authenticate. Upon successful authentication, the OIDC provider will send a callback request to the redirect URI which includes an authorization code (and some other data for validation)
- The callback server running in the background receives the request, extracts the authorization code, use that code to obtain *an access token* via *the token endpoint*.

### Improvements

- Add logic to validate the JWT exchanges to avoid MITM attacks
- Add [Proof Key for Code Exchange by OAuth Public Clients (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- Securely store the authorization code and access token.
- Implement the callback server using HTTPS because some OIDC providers do not accept `http://..` as redirect/callback URIs.

## License

MIT, of course.
