# orin-code-cli — command-line for Orin Code

Zero runtime dependencies, plain Node 18+.

```bash
npm i -g github:januththedev/orin-code-cli
# or: node orin.mjs <cmd>

orin login                  # Core device PKCE; browser approval
orin chat "explain closures"
echo "hi" | orin chat       # stdin works
orin chat "refactor this" --thinking
orin search "Kandy weather" -n 5
orin whoami
orin logout
```

## Credential boundary

`orin login` creates a Core PKCE S256 device grant. The 15-minute access token
is held in memory; the rotated 30-day refresh token is stored by the operating
system credential service:

- Windows: PowerShell DPAPI encrypted file;
- macOS: Keychain via `security`;
- Linux: Secret Service via `secret-tool`.

The CLI never writes a bearer or refresh token to `~/.orin.json` or another
plaintext file. `ORIN_TOKEN` is supported only for short-lived development;
production refresh requires the OS credential store. Legacy plaintext
`~/.orin.json` is removed on logout and is never loaded.

`ORIN_API` must be HTTPS (HTTP is accepted only for explicit localhost), and
verification URLs are opened with argument-based process APIs rather than a
shell command. `orin search` uses the public GET route, so queries are visible
in URLs; do not use it for confidential text. `orin run` is intentionally
disabled until Orin Tools has a reviewed Orin-controlled sandbox.
