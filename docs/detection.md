# Detection

What the engine detects, under which category names, and - just as
important - what it cannot detect. The category names are the interop
surface (spec 06): ports must not rename them, and neither do the adapters.

## Coverage taxonomy

`ALL_DETECTION_CATEGORIES` contains exactly these 19 category strings
(verbatim, spec 06):

```
xss, sqli, dir_traversal, path_traversal, cmd_injection, file_inclusion,
ldap, xml, ssrf, nosql, file_upload, template, http_split, sensitive_file,
cms_probing, recon, proto_pollution, code_injection, deserialization
```

Two additional category strings exist outside the set:

- `"custom"`: every user-added pattern, and the synthetic decode-budget
  threat.
- Semantic threats carry `attack_type` (not `category`); when a category is
  derived for events they map through the reference's semantic-to-category
  table (`xss`->`xss`, `sql`->`sqli`, `command`->`cmd_injection`,
  `path`->`path_traversal`, `template`->`template`, `suspicious`->`custom`;
  any other value passes through unchanged).

Categories scan source contexts (url_path, query_param, header,
request_body, unknown) per the spec 06 context table: `cmd_injection`,
`file_upload`, `sensitive_file`, `cms_probing`, and `recon` skip one context
each (`url_path` for the first two, `header` for the last three).

Configuration knobs: `enabled_detection_categories`,
`excluded_detection_headers`, `excluded_semantic_detection_headers`,
`excluded_detection_params`,
`excluded_detection_body_fields`, and the threshold family - all documented
in [Configuration](configuration.md) under Detection / penetration.

The `Cookie` header is scanned one `name=value` pair at a time (split on `;`,
spaces trimmed, empty pairs skipped), each pair through the same header path
and the same value budget, so a logged-in session cookie no longer scores as
one long value. An attack in any single pair is still detected, and
`excluded_semantic_detection_headers` applies per pair.

## Detection limits (bounded reads)

These limits are part of the contract (spec 01.2/01.4), not defects, and
they are the honest operating envelope of every guard family port:

- **Bounded request read.** When a request has no usable `Content-Length`
  (e.g. chunked encoding), the adapter's bounded body reader returns at most
  `detection_max_body_inspect_bytes` bytes from the start of the body, and
  implementations must not buffer more than that internally. Only the
  returned prefix is scanned: payloads beyond the cap, or signatures split
  across the boundary, are not detected. Absence of the capability is
  treated as "cannot bound the read": the engine never reads the full body
  as an implicit fallback - the body is not read at all and a one-time
  warning names the cap, the client, and which of the two happened.
- **Bounded response read.** Behavioral `return_pattern` rules with
  `behavior_scan_response_body` enabled read at most
  `behavior_max_response_body_inspect_bytes` of the outgoing body, teed so
  the full body still reaches the client, and never by consuming the
  underlying stream (indefinite streams such as SSE yield whatever prefix is
  available at a natural stopping point). Without the bounded response
  capability, body-based return patterns are skipped entirely.
- **Scan budgets.** `detection_max_scan_values` bounds the number of
  individual values scanned per request and `detection_max_scan_chars` the
  total characters handed to the pattern engine; beyond a cap the remainder
  is not scanned (fail-open with a one-time warning naming the client IP).
  `detection_max_json_depth` bounds structural JSON walking; at the cap the
  value is serialized and scanned as one value.

Every limit is enforced with the same posture: the engine prefers
under-scanning with a warning over unbounded reads, and the corpus
(safety_gates suite) pins the warning and verdict behavior.
