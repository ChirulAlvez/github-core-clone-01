# github-core-clone

A GitHub-compatible git forge in one dependency-free Node process: git smart
HTTP (upload-pack v2 / receive-pack v0), REST v3, GraphQL and MCP, all backed
by a single in-memory store. Git objects are kept byte-for-byte verbatim;
packs carry whole objects only (no deltas, deflate level 1).

## Run

```sh
MAKEFUN_ENV_URL=http://127.0.0.1:PORT \
MAKEFUN_SHOP_TOKEN=<token> \
MAKEFUN_TRIAL_NOW=<epoch seconds> \
node main.ts
```

`main.ts` binds an ephemeral port, registers it with the environment, then
long-polls the environment's `/done` endpoint and exits 0 when the trial ends.
`GET /healthz` answers 200 while the forge is up.

## Layout

- `main.ts` — lifecycle only: bind, register, poll `/done`, exit.
- `app.ts` — the whole forge: the in-memory store, git wire protocol
  (pkt-lines, packfiles, shallow fetch), REST v3, a small GraphQL parser and
  executor, and a JSON-RPC 2.0 MCP server. No dependencies, only
  `node:http`, `node:zlib` and `node:crypto`.

The viewer identity is the scenario viewer, `adaiversen` (id 1000): the shop
token carries no login and `POST /user/repos` carries no owner, so the login
is embedded as a constant, exactly as the trial scenario defines it.
Timestamps come from `MAKEFUN_TRIAL_NOW`, never from the wall clock.

## Verification

The kit's `grade-local` cannot run practice trials. The verified manual path
is: run `program/env/server.mjs` (with `MAKEFUN_STATE_DIR` and
`MAKEFUN_SHOP_TOKEN`), then this entry (with `MAKEFUN_ENV_URL` and the same
token), then `program/scorer/score.mjs` (with `MAKEFUN_EXPORT_DIR` and
`MAKEFUN_SCORES_DIR`).
