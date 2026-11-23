# Exhaustive ACL fixture

Made by protomolt (commit 390c1b4) from five Confluence-shaped documents and six identities.

- `exhaustive-items.ndjson`: the documents `gated` (allow, deny and one gate), `ungated` (allow and deny),
  `write-only` (only write rules, so no read keys), `gate-only` (a gate and deny but no allow) and `no-rules`.
- `exhaustive-callers.json`: 64 callers, `mask-0` to `mask-63`, one for every subset of the six identities, with
  the subset under `identities`, the expanded principal keys under `terms` and protomolt's `DocumentAccessPolicy`
  read decision for every document under `reads`.

Regenerate in protomolt and copy both files here; do not edit them by hand.
