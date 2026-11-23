# Confluence ACL fixture

Made by protomolt's `ConfluenceSecurityMappingTest` (commit 78a7c37) from
grpc-confluence Sync records recorded live on the CLAUDEGRPC test space (run 45099579044), with account ids and emails scrubbed.

- `confluence-items.ndjson`: one line per page, protomolt `DocumentSecurity` projected into the plugin's ACL fields
  by `DocumentSecurityTerms`.
- `confluence-callers.json`: per caller, the expanded and lower-cased principal keys and protomolt's own
  `DocumentAccessPolicy` read decision for every page. Callers are the join-proof email, each recorded account
  with its Confluence access classes, one account without access classes and a licensed outsider.

Regenerate in protomolt and copy both files here; do not edit them by hand.
