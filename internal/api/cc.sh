#!/bin/sh
# Auditable, no files, no installation, no second script. Requires curl >= 8.4.
# Origin is bound by server configuration, never inferred from stdin or Host.
set -f
# Do not let curl write TLS secrets through an inherited diagnostic setting.
unset SSLKEYLOGFILE
LC_ALL=C
export LC_ALL
origin='@ORIGIN@'
unknown() {
    printf '%s\n' 'terminal_observed_ip=unknown'
    printf '%s\n' "$1"
    exit "$2"
}
command -v curl >/dev/null 2>&1 || unknown 'cc: installed curl required' 2
version=$(curl -q --version 2>/dev/null) || unknown 'cc: curl unavailable' 2
version=${version#curl }
version=${version%% *}
case "$version" in *[!0-9.]*|'') unknown 'cc: unsupported curl version' 2 ;; esac
major=${version%%.*}
rest=${version#*.}
minor=${rest%%.*}
case "$major:$minor" in :*|*:|0*:*|*:0[0-9]*) unknown 'cc: unsupported curl version' 2 ;; esac
[ "${#major}" -le 3 ] && [ "${#minor}" -le 3 ] || unknown 'cc: unsupported curl version' 2
if [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -lt 4 ]; }; then
    unknown 'cc: curl >= 8.4 required for bounded unknown-length responses' 2
fi
printf 'curl_version=%s\n' "$version"
proxy=false
# Only presence is inspected; never print credentials or environment values.
if [ -n "${http_proxy+x}${https_proxy+x}${all_proxy+x}${HTTP_PROXY+x}${HTTPS_PROXY+x}${ALL_PROXY+x}${no_proxy+x}${NO_PROXY+x}" ]; then
    proxy=true
fi
printf 'proxy_environment_set=%s\n' "$proxy"
# curl deliberately ignores uppercase HTTP_PROXY (CGI security convention).
# Refuse ambiguous intent rather than translating credentials or going direct.
if [ -n "${HTTP_PROXY+x}" ]; then
    unknown 'cc: HTTP_PROXY is ignored by curl; review proxy configuration explicitly' 3
fi
printf 'origin=%s\n' "$origin"
printf '%s\n' 'source=configured-origin /cc/ip transport-peer observation (may be a reverse proxy)'
printf '%s\n' 'Proxy environment can affect the path; no direct fallback. Not an account safety or DNS leak test.'
# -q disables curlrc; no netrc, redirects, retries, verbose output or local data.
# Suppress curl errors: proxy URLs/credentials must not reach the terminal.
reply=$(curl -q --silent --fail --connect-timeout 3 --max-time 6 \
    --max-filesize 256 --proto '=http,https' --max-redirs 0 \
    --user-agent 'ipd-cc/1' --header 'Accept: text/plain' \
    --write-out '\n%{http_code}' "$origin/cc/ip" 2>/dev/null)
status=$?
[ "$status" -eq 0 ] || unknown 'cc: request failed (offline, timeout, size or HTTP error)' 3
code=${reply##*
}
[ "$code" = 200 ] || unknown 'cc: unexpected HTTP status' 3
value=${reply%
*}
# Permit one trailing LF (the endpoint's text format); nothing else.
value=${value%"
"}
[ "${#value}" -le 64 ] || unknown 'cc: malformed response' 4
# Exact minimal JSON is also accepted; no general JSON parser or evaluation.
case "$value" in
    '{"ip":"'*'"}') value=${value#'{"ip":"'}; value=${value%'"}'} ;;
esac
ipv4() {
    case "$1" in *[!0-9.]*|''|.*|*.|*..*) return 1 ;; esac
    oldIFS=$IFS; IFS=.; set -- $1; IFS=$oldIFS
    [ "$#" -eq 4 ] || return 1
    for part do
        case "$part" in ''|0[0-9]*|????*) return 1 ;; esac
        [ "$part" -le 255 ] || return 1
    done
}
ipv6() {
    case "$1" in *[!0-9a-fA-F:]*|''|*:::*) return 1 ;; esac
    compressed=false
    case "$1" in
        *::*)
            compressed=true
            tail=${1#*::}
            case "$tail" in :*|*:) return 1 ;; esac
            case "$tail" in *::*) return 1 ;; esac
            groups=${1%%::*}
            [ -z "$groups" ] || [ -z "$tail" ] || groups=$groups:
            groups=$groups$tail
            ;;
        *) groups=$1; case "$groups" in :*|*:) return 1 ;; esac ;;
    esac
    oldIFS=$IFS; IFS=:; set -- $groups; IFS=$oldIFS
    for part do case "$part" in ''|?????*) return 1 ;; esac; done
    if [ "$compressed" = true ]; then [ "$#" -lt 8 ]; else [ "$#" -eq 8 ]; fi
}
case "$value" in
    *:*) ipv6 "$value" || unknown 'cc: malformed response' 4 ;;
    *.*) ipv4 "$value" || unknown 'cc: malformed response' 4 ;;
    unknown) unknown 'cc: endpoint has no observation' 3 ;;
    *) unknown 'cc: malformed response' 4 ;;
esac
printf 'terminal_observed_ip=%s\n' "$value"
printf '%s\n' 'Observation only; does not establish other services see the same IP.'
exit 0
