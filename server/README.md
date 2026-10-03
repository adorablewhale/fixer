# basic diagnostics server

the open-source reporting module is `fixer.mjs`, with its sqlite/d1 tables in `0010.sql`. it is integrated into adorablewhale's existing matcha dashboard. it contains no website, cloudflare, discord or administrator credential.

the existing dashboard's authentication and infrastructure stay separate. importing this module does not grant access to them. a self-hosted service needs a d1-compatible `DB`, `ORIGIN` set to its exact https origin, and rate-limit bindings `API_LIMIT` and `REGISTER_LIMIT`. update the client's fixed origin and policy if deploying a different service.

## integration

import `createFixer`, create it with the worker environment, and dispatch `/api/fixer/register`, `/api/fixer/report`, and `/api/fixer/delete` to `fixer.client(request)`. keep the existing same-origin checks. dispatch `GET /api/admin/fixer` to `fixer.admin()` only after the existing admin authentication succeeds. call `fixer.cleanup()` from scheduled maintenance. apply the migration before deploying the worker.

the admin response contains a 30-day summary and the latest 200 run snapshots. only installation and run prefixes appear in that response. the existing private admin tab renders these values as text.

## protocol

each consenting installation generates a 2048-bit rsa key with exponent 65537. registration accepts its public jwk (`kty`, `n`, `e`) and the current disclosure policy. the installation id is the lowercase hex sha256 of `RSA\n<n>\n<e>`. the registration must itself be signed with that key.

requests use rsa pkcs1-v1.5 with sha256 over these utf8 lines, without a trailing newline:

```text
fixer-report-v1
POST
<https origin><path>
<installation id, or - for enrollment>
<unix timestamp>
<random 32-character hex nonce>
<base64 sha256 of the exact body bytes>
```

headers: `x-fixer-id`, `x-fixer-time`, `x-fixer-nonce`, `x-fixer-signature` (base64). timestamps must be within five minutes. nonce fingerprints expire after ten minutes; deletion keeps them until then so a captured enrollment cannot recreate deleted history. deletion body is `{}` and removes only that key's installation and runs.

reports accept an exact schema of short enums and bounded numbers; arbitrary text, keys, paths and logs are rejected. each run is one latest-status row. sequences must increase and an ended run cannot resume. bodies are capped at 4096 bytes. tls uses normal certificate verification. no shared client secret, certificate bypass or administrative credential is used.

## boundaries

signatures prove possession of an installation key, not that a person really ran an unmodified client. public enrollment cannot prevent somebody generating their own keys and invented runs. rate limits and quotas reduce abuse; cloudflare rate limits apply per location, not as an absolute global guarantee. there are global enrollment and per-installation daily run caps. these are diagnostic counts, not verified analytics or billing data.

the client encrypts its private key using windows dpapi for the current user. server data uses cloudflare's storage protections and private admin access; report fields are stored in queryable form, not end-to-end encrypted. cloudflare necessarily handles the connecting ip for transport and throttling, but this module stores no ip addresses. existing server credentials remain worker secrets.

client code and this server module are mit licensed. the private dashboard's unrelated code and credentials are not included in the public client package.

## current file reference

`fixer-release.mjs` exposes only the checked standard release's sha256 hashes, sizes and upstream metadata at `GET /api/fixer/release`. it accepts only the three fixed `https://files.matcha.pink/normal/` urls. a hash reference must be under 24 hours old, and a fresh tls head check must match its metadata; stale or changed references return an unavailable response. no executable is served by this endpoint. pro / beta references are not provided.

`refresh-release.mjs` streams those official downloads into sha256 without saving or executing them, checks metadata before/during/after and validates the exe signature bytes and size bounds. run it with node 24:

```text
node refresh-release.mjs release.json
```

publication adds `--publish` and reads `FIXER_RELEASE_UPDATE_KEY` from the process environment. that scoped server-side secret can replace only the validated public reference at `POST /api/internal/fixer/release`; it has no admin or reporting authority. never embed it in the client or source, write it to a request url, or publish it in a log. the publisher rejects oversized, stale, changed or substituted references and has its own authentication rate limit.

the private matcha-kit repository runs an hourly github actions job. its scoped credential is kept in github actions and cloudflare worker secrets, and is absent from the public client repository. the updater refreshes only the public file reference. a failed or delayed refresh eventually makes the reference expire; the client labels reference unavailability and keeps the original loader's update check available.
