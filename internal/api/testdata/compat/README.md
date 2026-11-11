# API compatibility fixtures

Synthetic responses in the shapes the WARP consumer API answered with when OpenWarp was verified live
(2026-11-10). They contain **no real data**: ids, tokens, keys and addresses are placeholders.
`compat_test.go` checks that every field OpenWarp relies on is still read from them, and how the client
behaves when a response changes shape. When Cloudflare changes a response, add a fixture of the new
shape here first (redacted), then adapt the client.

| File | Shape |
|---|---|
| `register-v0a4471.json` | `POST /v0a4471/reg`, bare object (Android identity) |
| `register-v0.json` | `POST /v0/reg`, `{"result": …, "success": true}` envelope (macOS identity) |
| `key-patch-masque-v0.json` | `PATCH /v0/reg/{id}` enrolling a MASQUE key, enveloped |
| `account-v0.json` | `GET /v0/reg/{id}/account`, enveloped |
| `devices-v0a4471.json` | `GET /v0a4471/reg/{id}/account/devices`, bare array |
| `register-extra-fields.json` | registration with fields OpenWarp does not know (must be ignored) |
