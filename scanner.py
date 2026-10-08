#!/usr/bin/env python3
"""HTTP Security Header Checker.

Fetches one URL, follows redirects, and checks the *final* HTTP response for
six security-related response headers using small, deterministic rules.

PASS means "the response satisfied this tool's basic rule". It does NOT mean
the website is secure, and a FAIL means "missing recommended security header",
not "vulnerable". See README.md for the exact rules and the limitations.

Exit codes:
    0  scan completed, no FAIL results
    1  scan completed, one or more FAIL results (or WARN with --fail-on-warn)
    2  invalid usage, or the scan could not be completed (network error etc.)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Dict, List, Mapping, Optional, Sequence
from urllib.parse import urlparse

import requests

__version__ = "1.0.0"

DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 10
USER_AGENT = f"security-header-checker/{__version__}"
MAX_TEXT_VALUE_LENGTH = 120  # only affects human-readable output, never JSON

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"  # rule not applicable (HSTS on a plain-HTTP final URL)

EXIT_OK = 0
EXIT_FAIL_FOUND = 1
EXIT_ERROR = 2

DISCLAIMER = (
    "PASS means the response met this tool's simplified basic rule. It does "
    "not mean the site is secure. FAIL means a recommended header was not "
    "found in the final response. WARN results need human review."
)

# Referrer-Policy values this tool treats as PASS. Any other recognised value
# (for example unsafe-url) is a WARN.
SAFE_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)
OTHER_REFERRER_POLICIES = frozenset(
    {
        "unsafe-url",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
    }
)
KNOWN_REFERRER_POLICIES = SAFE_REFERRER_POLICIES | OTHER_REFERRER_POLICIES

# CSP source expressions that make frame-ancestors allow (almost) any parent.
PERMISSIVE_FRAME_ANCESTOR_TOKENS = frozenset({"*", "http:", "https:"})

MISSING = "missing recommended security header"


class ScanError(Exception):
    """A scan could not be completed (bad URL, network failure, ...)."""

    def __init__(self, error_type: str, message: str) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.message = message


@dataclass
class HeaderResult:
    """Outcome of one header rule."""

    header: str
    status: str
    value: Optional[str]
    message: str


@dataclass
class FetchResult:
    """What we keep from the final HTTP response."""

    final_url: str
    status_code: int
    redirects: int
    headers: Dict[str, str]


# --------------------------------------------------------------------------
# Small parsing helpers
# --------------------------------------------------------------------------

def normalize_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    """Return a copy of *headers* with lower-cased names (case-insensitive)."""
    return {str(name).lower(): str(value) for name, value in headers.items()}


def parse_csp(value: str) -> Dict[str, List[str]]:
    """Parse a CSP string into {directive-name: [tokens]}.

    Names are lower-cased. If a directive appears twice the first one wins,
    which matches how browsers treat duplicates.
    """
    directives: Dict[str, List[str]] = {}
    for chunk in value.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        if name not in directives:
            directives[name] = parts[1:]
    return directives


def _split_top_level(value: str, separator: str = ",") -> Optional[List[str]]:
    """Split on *separator* outside parentheses. None if parentheses are unbalanced."""
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        if char == separator and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if depth != 0:
        return None
    parts.append("".join(current))
    return parts


# --------------------------------------------------------------------------
# Rules: one function per header. Each takes lower-cased headers.
# --------------------------------------------------------------------------

def check_hsts(headers: Mapping[str, str], is_https: bool) -> HeaderResult:
    """Strict-Transport-Security.

    * Plain-HTTP final URL: SKIP (browsers ignore HSTS over HTTP, so a missing
      header there is not judged).
    * HTTPS: FAIL if absent; WARN if max-age is missing, invalid or 0;
      otherwise PASS.
    """
    name = "Strict-Transport-Security"
    value = headers.get("strict-transport-security")
    if not is_https:
        return HeaderResult(
            name, SKIP, value,
            "Not evaluated: the final URL is plain HTTP and HSTS is only "
            "honoured over HTTPS.",
        )
    if value is None:
        return HeaderResult(name, FAIL, None, f"{MISSING}.")

    max_age: Optional[str] = None
    for directive in value.split(";"):
        key, _, raw = directive.partition("=")
        if key.strip().lower() == "max-age":
            max_age = raw.strip().strip('"')
            break
    if max_age is None or not re.fullmatch(r"\d+", max_age):
        return HeaderResult(
            name, WARN, value, "Present, but max-age is missing or not a number."
        )
    if int(max_age) == 0:
        return HeaderResult(
            name, WARN, value, "max-age=0 tells browsers to remove HSTS for this host."
        )
    return HeaderResult(name, PASS, value, "Present with a valid max-age.")


def check_csp(headers: Mapping[str, str]) -> HeaderResult:
    """Content-Security-Policy.

    FAIL if absent. WARN if empty, or if the effective script directive
    (script-src, else default-src) allows 'unsafe-eval' or an effective
    'unsafe-inline'. 'unsafe-inline' is ignored by browsers when a nonce, hash
    or 'strict-dynamic' is present in the same directive, so it is not flagged
    in that case. Otherwise PASS.
    """
    name = "Content-Security-Policy"
    value = headers.get("content-security-policy")
    if value is None:
        message = f"{MISSING}."
        if "content-security-policy-report-only" in headers:
            message = (
                f"{MISSING}. Only Content-Security-Policy-Report-Only was "
                "found, which reports violations but does not enforce a policy."
            )
        return HeaderResult(name, FAIL, None, message)
    if not value.strip():
        return HeaderResult(name, WARN, value, "Present but empty.")

    directives = parse_csp(value)
    script_tokens = directives.get("script-src", directives.get("default-src", []))
    lowered = [token.lower() for token in script_tokens]

    problems: List[str] = []
    if "'unsafe-eval'" in lowered:
        problems.append("'unsafe-eval'")
    if "'unsafe-inline'" in lowered:
        neutralised = any(
            token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
            or token == "'strict-dynamic'"
            for token in lowered
        )
        if not neutralised:
            problems.append("'unsafe-inline'")
    if problems:
        return HeaderResult(
            name, WARN, value,
            "Script sources allow " + " and ".join(problems)
            + ", which weakens the policy.",
        )
    return HeaderResult(name, PASS, value, "Present with a non-empty value.")


def check_x_content_type_options(headers: Mapping[str, str]) -> HeaderResult:
    """X-Content-Type-Options: PASS only for nosniff (case-insensitive)."""
    name = "X-Content-Type-Options"
    value = headers.get("x-content-type-options")
    if value is None:
        return HeaderResult(name, FAIL, None, f"{MISSING}.")
    # Browsers use the first comma-separated value.
    first = value.split(",")[0].strip().lower()
    if first == "nosniff":
        return HeaderResult(name, PASS, value, "Value is nosniff.")
    return HeaderResult(name, WARN, value, "Present, but the value is not nosniff.")


def check_x_frame_options(headers: Mapping[str, str]) -> HeaderResult:
    """X-Frame-Options, with CSP frame-ancestors accepted as an alternative.

    PASS if X-Frame-Options is DENY or SAMEORIGIN, or if a CSP frame-ancestors
    directive restricts embedding (non-empty and not '*', 'http:' or 'https:').
    WARN if X-Frame-Options is present but unrecognised and no restrictive
    frame-ancestors exists. FAIL if neither mechanism is present.
    """
    name = "X-Frame-Options"
    value = headers.get("x-frame-options")
    csp = headers.get("content-security-policy")

    if value is not None and value.strip().upper() in {"DENY", "SAMEORIGIN"}:
        return HeaderResult(name, PASS, value, "Value is DENY or SAMEORIGIN.")

    ancestors: Optional[List[str]] = None
    if csp:
        ancestors = parse_csp(csp).get("frame-ancestors")
    if ancestors and not any(
        token.lower() in PERMISSIVE_FRAME_ANCESTOR_TOKENS for token in ancestors
    ):
        return HeaderResult(
            name, PASS, value,
            "Embedding is restricted by CSP frame-ancestors "
            f"({' '.join(ancestors)}); X-Frame-Options is not required.",
        )

    if value is not None:
        return HeaderResult(
            name, WARN, value,
            "Unrecognised value (expected DENY or SAMEORIGIN; ALLOW-FROM is "
            "obsolete) and no restrictive CSP frame-ancestors found.",
        )
    return HeaderResult(
        name, FAIL, None,
        f"{MISSING}, and no restrictive CSP frame-ancestors directive was found.",
    )


def check_referrer_policy(headers: Mapping[str, str]) -> HeaderResult:
    """Referrer-Policy.

    The header may be a comma-separated fallback list; like browsers, the last
    *recognised* value is used. PASS for no-referrer, same-origin,
    strict-origin, strict-origin-when-cross-origin. Any other value is WARN.
    """
    name = "Referrer-Policy"
    value = headers.get("referrer-policy")
    if value is None:
        return HeaderResult(name, FAIL, None, f"{MISSING}.")
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    if not tokens:
        return HeaderResult(name, WARN, value, "Present but empty.")
    recognised = [t for t in tokens if t in KNOWN_REFERRER_POLICIES]
    if not recognised:
        return HeaderResult(name, WARN, value, "No recognised Referrer-Policy value.")
    effective = recognised[-1]
    if effective in SAFE_REFERRER_POLICIES:
        return HeaderResult(name, PASS, value, f"Effective policy is {effective}.")
    return HeaderResult(
        name, WARN, value,
        f"Effective policy is {effective}, which is not in this tool's safer list.",
    )


_PERMISSIONS_ENTRY = re.compile(
    r"[a-z][a-z0-9*_.-]*=(\*|\([^()]*\))(;.*)?", re.IGNORECASE
)


def check_permissions_policy(headers: Mapping[str, str]) -> HeaderResult:
    """Permissions-Policy.

    FAIL if absent. WARN if empty or if it does not look like a list of
    ``feature=(...)`` / ``feature=*`` entries. Otherwise PASS. Which features
    are listed is not judged.
    """
    name = "Permissions-Policy"
    value = headers.get("permissions-policy")
    if value is None:
        return HeaderResult(name, FAIL, None, f"{MISSING}.")
    if not value.strip():
        return HeaderResult(name, WARN, value, "Present but empty.")
    entries = _split_top_level(value)
    if entries is None or not all(
        _PERMISSIONS_ENTRY.fullmatch(entry.strip()) for entry in entries
    ):
        return HeaderResult(
            name, WARN, value,
            "Could not parse as feature=(...) entries under this tool's "
            "simplified rules; review manually.",
        )
    return HeaderResult(name, PASS, value, "Present and well-formed.")


# --------------------------------------------------------------------------
# Evaluation and reporting
# --------------------------------------------------------------------------

HEADER_NAMES = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def evaluate_headers(headers: Mapping[str, str], is_https: bool) -> List[HeaderResult]:
    """Run every rule against *headers* (names are matched case-insensitively)."""
    h = normalize_headers(headers)
    return [
        check_hsts(h, is_https),
        check_csp(h),
        check_x_content_type_options(h),
        check_x_frame_options(h),
        check_referrer_policy(h),
        check_permissions_policy(h),
    ]


def summarize(results: Sequence[HeaderResult]) -> Dict[str, int]:
    """Count results per status."""
    counts = {"pass": 0, "warn": 0, "fail": 0, "skip": 0}
    for result in results:
        counts[result.status.lower()] += 1
    return counts


def validate_url(raw: str) -> str:
    """Return a cleaned URL or raise ScanError(invalid_url)."""
    url = raw.strip()
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ScanError(
            "invalid_url",
            f"Invalid URL {raw!r}: it must start with http:// or https://",
        )
    try:
        host = parsed.hostname
        parsed.port  # noqa: B018 - raises ValueError for an out-of-range port
    except ValueError:
        raise ScanError("invalid_url", f"Invalid URL {raw!r}: bad port number.")
    if not host:
        raise ScanError("invalid_url", f"Invalid URL {raw!r}: no host name found.")
    if parsed.username or parsed.password:
        raise ScanError(
            "invalid_url",
            "URLs containing a username or password are not supported "
            "(credentials could leak into logs).",
        )
    return url


def _is_dns_error(exc: BaseException) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    markers = (
        "nameresolutionerror",
        "name or service not known",
        "getaddrinfo failed",
        "temporary failure in name resolution",
        "nodename nor servname",
        "failed to resolve",
        "no address associated with hostname",
    )
    return any(marker in text for marker in markers)


def _short_reason(exc: BaseException) -> str:
    """A compact reason such as '[Errno 111] Connection refused', if present."""
    match = re.search(r"\[Errno -?\d+\] [^'\")]+", str(exc))
    return match.group(0) if match else type(exc).__name__


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> FetchResult:
    """GET *url*, follow redirects, and return the final response's headers.

    Only headers are read; the body is not downloaded. Every expected failure
    is converted to ScanError.
    """
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    response = None
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": USER_AGENT},
        )
        return FetchResult(
            final_url=response.url,
            status_code=response.status_code,
            redirects=len(response.history),
            headers=dict(response.headers),
        )
    except requests.exceptions.SSLError as exc:
        raise ScanError("tls_error", f"TLS/SSL error while connecting to {url}: {exc}")
    except requests.exceptions.Timeout:
        raise ScanError("timeout", f"Timed out after {timeout:g} seconds: {url}")
    except requests.exceptions.TooManyRedirects:
        raise ScanError(
            "too_many_redirects",
            f"More than {MAX_REDIRECTS} redirects while requesting {url}.",
        )
    except (
        requests.exceptions.MissingSchema,
        requests.exceptions.InvalidSchema,
        requests.exceptions.InvalidURL,
    ) as exc:
        raise ScanError("invalid_url", f"Invalid URL {url!r}: {exc}")
    except requests.exceptions.ConnectionError as exc:
        if _is_dns_error(exc):
            raise ScanError("dns_error", f"DNS lookup failed: could not resolve the host in {url}.")
        raise ScanError(
                "connection_error",
                f"Could not connect to {url} ({_short_reason(exc)}).",
            )
    except requests.exceptions.RequestException as exc:
        raise ScanError("request_error", f"Request failed for {url}: {exc}")
    finally:
        if response is not None:
            response.close()
        session.close()


def build_report(target: str, fetched: FetchResult) -> Dict[str, object]:
    """Turn a FetchResult into the report dictionary used for text and JSON."""
    final_scheme = urlparse(fetched.final_url).scheme.lower()
    is_https = final_scheme == "https"
    results = evaluate_headers(fetched.headers, is_https)

    notes: List[str] = []
    if fetched.redirects:
        notes.append(
            "Only the final response after redirects was checked; headers on "
            "intermediate redirect responses were not evaluated."
        )
    if urlparse(target).scheme.lower() == "https" and not is_https:
        notes.append("The request started on HTTPS but ended on plain HTTP.")
    if fetched.status_code >= 400:
        notes.append(
            f"The final response was HTTP {fetched.status_code}. Error pages "
            "often carry different headers than normal pages."
        )

    return {
        "tool": {"name": "security-header-checker", "version": __version__},
        "target": target,
        "final_url": fetched.final_url,
        "status_code": fetched.status_code,
        "redirects": fetched.redirects,
        "redirected": fetched.redirects > 0,
        "headers_checked": len(results),
        "summary": summarize(results),
        "results": [asdict(r) for r in results],
        "notes": notes,
    }


def scan(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, object]:
    """Validate, fetch and evaluate *url*; return the report dictionary."""
    cleaned = validate_url(url)
    return build_report(cleaned, fetch(cleaned, timeout))


def _clean(text: str) -> str:
    """Make text safe for any console.

    Control characters (e.g. terminal escape codes sent by a server) and
    non-ASCII characters are replaced with '?'. JSON output is unaffected.
    """
    return "".join(ch if ch.isprintable() and ord(ch) < 127 else "?" for ch in text)


def format_text(report: Mapping[str, object]) -> str:
    """Render the human-readable report."""
    summary = report["summary"]
    lines = [
        "# HTTP Security Header Checker",
        "",
        f"Requested URL: {_clean(str(report['target']))}",
        f"Final URL: {_clean(str(report['final_url']))}",
        f"Status: {report['status_code']}",
        f"Redirects: {report['redirects']}"
        + (" (redirected)" if report["redirected"] else " (none)"),
        "",
        "## Security Headers",
        "",
    ]
    for result in report["results"]:
        lines.append(f"[{result['status']}] {result['header']}")
        value = result["value"]
        if value is not None:
            value = _clean(value)
            if len(value) > MAX_TEXT_VALUE_LENGTH:
                value = value[: MAX_TEXT_VALUE_LENGTH - 3] + "..."
            lines.append(f"       value:  {value}")
        lines.append(f"       reason: {result['message']}")
    lines += [
        "",
        "## Summary",
        "",
        f"PASS: {summary['pass']}",
        f"WARN: {summary['warn']}",
        f"FAIL: {summary['fail']}",
        f"SKIP: {summary['skip']}",
    ]
    if report["notes"]:
        lines += ["", "## Notes", ""]
        lines += [f"- {note}" for note in report["notes"]]
    lines += ["", DISCLAIMER]
    return "\n".join(lines)


def exit_code_for(report: Mapping[str, object], fail_on_warn: bool = False) -> int:
    """0 = no FAIL, 1 = at least one FAIL (or WARN with fail_on_warn)."""
    summary = report["summary"]
    if summary["fail"] > 0 or (fail_on_warn and summary["warn"] > 0):
        return EXIT_FAIL_FOUND
    return EXIT_OK


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def _positive_float(raw: str) -> float:
    try:
        number = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{raw!r} is not a number")
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "Check one URL's final HTTP response for six recommended security "
            "headers. Only scan sites you own or have permission to assess. "
            "PASS means the basic rule was met, not that the site is secure."
        ),
        epilog=(
            "exit codes: 0 = no FAIL results; 1 = one or more FAIL results "
            "(or WARN with --fail-on-warn); 2 = invalid usage or scan error."
        ),
    )
    parser.add_argument("url", help="URL to check, including http:// or https://")
    parser.add_argument(
        "--json", action="store_true",
        help="print a single JSON document (and nothing else) to stdout",
    )
    parser.add_argument(
        "--timeout", type=_positive_float, default=DEFAULT_TIMEOUT, metavar="SECONDS",
        help=f"network timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--fail-on-warn", action="store_true",
        help="also exit with code 1 when there are WARN results",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="write the report (JSON with --json, otherwise text) to FILE as "
             "UTF-8 instead of printing it; errors are still printed",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the exit code."""
    args = build_parser().parse_args(argv)  # exits with code 2 on bad usage
    try:
        report = scan(args.url, args.timeout)
    except ScanError as err:
        if args.json:
            print(json.dumps(
                {"target": args.url,
                 "error": {"type": err.error_type, "message": err.message}},
                indent=2,
            ))
        else:
            print(f"Error: {_clean(err.message)}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return EXIT_ERROR

    rendered = json.dumps(report, indent=2) if args.json else format_text(report)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(rendered + "\n")
        except OSError as exc:
            print(f"Error: could not write {_clean(args.output)}: {exc.strerror or exc}",
                  file=sys.stderr)
            return EXIT_ERROR
    else:
        print(rendered)
    return exit_code_for(report, args.fail_on_warn)


if __name__ == "__main__":
    sys.exit(main())
