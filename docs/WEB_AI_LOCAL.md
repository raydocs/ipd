# Web AI local increment

The existing lookup, timezone button and WebRTC upload are unchanged. The new
AI panel runs no probe until its collection button is clicked. Data lives only
in the page's memory/DOM (not storage); reloading discards it. No requests are
made by either new button. The optional JSON import consumes the existing
`Report.data.schema_version = ai-diagnosis-v1` contract from `ipd ai --json`;
it does not call a server endpoint or run the CLI.

Local fields: collection time, IANA timezone, UTC offset minutes, at most ten
language preferences, three fixed font layout comparisons (Arial, Times New
Roman, Courier New), UA WebView hints and navigator.webdriver. Missing or
throwing APIs yield null. Font measurements are approximate; fallback/privacy
settings can distort them. No canvas, hashes, font list enumeration or unique
identity is produced. WebView hint absence remains unknown. webdriver=false
is only the browser-reported value, not proof of manual use.

Imported traces require status=observed, evidence, a source and a valid literal
IP to form a group. `per_service.seen_ip` alone is not promoted into an observed
IP. Groups preserve trace URL/evidence and identify the scope as imported probe
process, not the current browser. Raw service availability evidence is shown
separately. The v1 contract has no per-observation timestamp, so times are null;
report cached_at and local collection time are never used as trace timestamps.
IPv4 and IPv6 are compared separately. Same IP is not proof of identical paths,
AI application observations, account access, or safety.

Stable recommendation order: missing expected trace/service evidence, multiple
same-family exits, uncollected local signals, manual timezone/language review,
then positive WebView/automation hints. Local hints never alter imported service
availability or diagnose account restrictions. No automatic timezone-to-country
mapping, fingerprint identity, or IP-ban attribution. This is a minimal local
viewer, not a full browser/network diagnosis. It adds no backend, runner or CLI
behavior. Tests use synthetic/documentation addresses only. No browser or live
service verification is claimed.
