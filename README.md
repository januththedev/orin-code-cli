# orin-code-cli — command-line for Orin Code

Zero dependencies. Plain Node 18+. Never holds AI keys.

```bash
npm i -g github:januththedev/orin-code-cli
# or: node orin.mjs <cmd>

orin login                  # pair this machine (browser approves once)
orin chat "explain closures"
echo "hi" | orin chat       # stdin works
orin chat "refactor this" --thinking
orin search "kandy weather" -n 5
orin run -l python -c "print(42)"
orin run -l go -f main.go
orin whoami
orin logout
```

Token lives in `~/.orin.json` (0600). Overrides: `ORIN_TOKEN`, `ORIN_API`, `ORIN_TOOLS`.
