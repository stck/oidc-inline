# oidc-inline

A headless OIDC authentication client for [authentik](https://goauthentik.io/) that replaces the browser in OAuth2 authorization code flows. It programmatically completes login (username, password, TOTP) and consent stages, then delivers the authorization code to the local callback.

Designed to be used as a `BROWSER` replacement for CLI tools like [NetBird](https://netbird.io/) that open a browser for OIDC login.

## How it works

1. Receives the OAuth2 authorization URL as an argument (the URL a CLI tool would normally open in a browser).
2. Follows the HTTP redirect chain through the relay/proxy to authentik's `/application/o/authorize/` endpoint.
3. Discovers the authentication flow and its query parameters from authentik's redirect to `/if/flow/:slug/`.
4. Executes the flow via authentik's API (`/api/v3/flows/executor/:slug/`), solving each stage:
   - **Identification** -- submits the username/email
   - **Password** -- submits the password
   - **TOTP** -- generates and submits a time-based one-time password
   - **Consent** -- accepts the consent challenge
5. After authentication, follows the redirect back to the authorize endpoint which triggers the authorization flow (consent/code issuance).
6. Follows the final redirect chain (relay callback -> localhost callback) to deliver the authorization code, just as a browser would.

## Installation

```bash
go build -o oidc-inline main.go
```

## Configuration

Create a `config.yaml` in the working directory or next to the binary:

```yaml
base_url: https://authentik.example.com/
username: user@example.com
password: your-password
totp_secret: YOUR_TOTP_SECRET_BASE32
socks5: socks5://user:pass@proxy:1080  # optional
```

| Field | Required | Description |
|-------|----------|-------------|
| `base_url` | Yes | Base URL of your authentik instance |
| `username` | Yes | Username or email for authentication |
| `password` | Yes | Account password |
| `totp_secret` | Yes | Base32-encoded TOTP secret for 2FA |
| `socks5` | No | SOCKS5 proxy URL (localhost traffic bypasses proxy) |

## Usage

```bash
# Direct invocation
./oidc-inline 'https://relay.example.com/oauth2/auth?client_id=my-app&...'

# As a BROWSER env for NetBird
export BROWSER=/path/to/oidc-inline
netbird up

# With custom config path
./oidc-inline --config /etc/oidc-inline/config.yaml 'https://...'
```

## Docker

The published Docker image is based on `ghcr.io/11notes/netbird-client:0.70` with `oidc-inline` pre-installed at `/etc/oidc-inline` and `BROWSER` env set accordingly.

```bash
docker pull ghcr.io/stck/oidc-inline:latest
```

Mount your `config.yaml` into the container:

```bash
docker run -v ./config.yaml:/etc/oidc-inline/config.yaml ghcr.io/stck/oidc-inline:latest
```
