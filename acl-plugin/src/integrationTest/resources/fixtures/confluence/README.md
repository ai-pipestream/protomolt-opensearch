# Confluence ACL fixture

Made by protomolt's `ConfluenceSecurityMappingTest` (branch `claude/project-thread-wfp1ob`, regenerated 2026-11-22 21:23 UTC) from
grpc-confluence Sync records recorded live on the CLAUDEGRPC test space, with account ids and emails scrubbed.

- `confluence-items.ndjson`: one line per page, protomolt `DocumentSecurity` projected into the plugin's ACL fields
  by `DocumentSecurityTerms`.
- `confluence-callers.json`: per caller, the expanded and lower-cased principal keys and protomolt's own
  `DocumentAccessPolicy` read decision for every page.

Regenerate in protomolt and copy both files here; do not edit them by hand.
