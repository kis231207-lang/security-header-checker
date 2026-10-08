# HTTP Security Header Checker

A small Python command-line tool that checks one URL's HTTP response for six recommended security headers and reports each as PASS, WARN, FAIL or SKIP. It prints a readable report or a single JSON document, and its exit code works in CI.

> **Read this first:** PASS means the response met this tool's *simplified basic rule*. It does **not** mean the website is secure. FAIL means a *missing recommended security header*, not that the site is vulnerable.

## Overview

`scanner.py` sends one GET request, follows redirects, and evaluates the headers of the **final** response against fixed, deterministic rules (listed below). It reads only the response headers, not the page body.

## Problem Statement

Checking whether a site sends the expected security response headers, and whether their values look sensible, means opening browser dev tools or running `curl`, reading the headers by eye, and comparing them to a mental checklist. This tool solves exactly that one problem: **automatically check a URL's final response for six specific security headers and report the result in a form that both people and CI can consume.**

It is not a vulnerability scanner.

## Why This Tool Exists

Checking headers by hand is repetitive and easy to get wrong (case differences, header lists, a policy hidden in a long CSP string). The rules here are written down, deterministic and small enough to audit, so the same input always gives the same verdict and every verdict can be checked against the raw response. Small and checkable was chosen over broad, because a noisy tool gets switched off.

## Features

- One clear job: six headers, fixed rules, no guessing
- Case-insensitive header handling
- Four statuses: `PASS`, `WARN`, `FAIL`, and `SKIP` (rule not applicable)
- Follows redirects; reports requested URL, final URL, status code and redirect count
- Valid, machine-readable JSON with `--json` (stdout contains JSON and nothing else)
- CI-friendly exit codes (`0` / `1` / `2`), optional `--fail-on-warn`
- Clean errors (invalid URL, DNS, connection, timeout, TLS, too many redirects) with no Python traceback
- CSP `frame-ancestors` accepted as a valid alternative to `X-Frame-Options`
- Automated tests that use a local server and mocks only (no external websites)
- One runtime dependency: `requests`

## Requirements

- Python 3.9 or newer
- `requests` (installed from `requirements.txt`)

## Installation

Windows (Command Prompt or PowerShell):

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

macOS / Linux:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
python scanner.py https://example.com
python scanner.py https://example.com --json
python scanner.py https://example.com --json --output report.json
python scanner.py https://example.com --timeout 5 --fail-on-warn
python scanner.py --help
```

| Option | Meaning |
| --- | --- |
| `url` | URL to check. Must start with `http://` or `https://`. URLs containing a username/password are rejected so credentials cannot leak into logs. |
| `--json` | Print one JSON document (and nothing else) to stdout. |
| `--output FILE` | Write the report to `FILE` as UTF-8 instead of printing it. Recommended on Windows PowerShell 5.1, where `>` writes UTF-16. |
| `--timeout SECONDS` | Network timeout. Default 10. |
| `--fail-on-warn` | Also exit with code 1 when any WARN result exists. |
| `--version` | Print the version. |

## Headers Checked

The rules are intentionally simple. Anything not listed here is not checked.

| Header | What it checks | Basic rule |
| --- | --- | --- |
| `Strict-Transport-Security` | Browser is told to use HTTPS only | Evaluated **only if the final URL is HTTPS**. FAIL if absent. WARN if `max-age` is missing, not a number, or `0`. Otherwise PASS. On a plain-HTTP final URL the result is **SKIP** (see below). |
| `Content-Security-Policy` | An enforced CSP exists and its script sources are not trivially weak | FAIL if absent (a `Content-Security-Policy-Report-Only` header alone does not count). WARN if empty, or if the effective script directive (`script-src`, else `default-src`) allows `'unsafe-eval'`, or allows `'unsafe-inline'` with no nonce, hash or `'strict-dynamic'` in the same directive. Otherwise PASS. |
| `X-Content-Type-Options` | MIME sniffing is disabled | PASS only for `nosniff` (case-insensitive). WARN for any other value. FAIL if absent. |
| `X-Frame-Options` | Clickjacking protection (framing restriction) | PASS if the header is `DENY` or `SAMEORIGIN` **or** if CSP has a `frame-ancestors` directive that is non-empty and does not contain `*`, `http:` or `https:`. WARN if the header is present but unrecognised and no such CSP directive exists. FAIL if neither mechanism is present. |
| `Referrer-Policy` | How much referrer information is sent | Uses the last *recognised* value in a comma-separated list, as browsers do. PASS for `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin`. WARN for any other value (for example `unsafe-url`), for an empty value, or if no value is recognised. FAIL if absent. |
| `Permissions-Policy` | Browser features policy is declared | FAIL if absent. WARN if empty or if it does not parse as comma-separated `feature=(...)` / `feature=*` entries. Otherwise PASS. Which features are restricted is **not** judged. |

### Why HSTS is SKIP on plain HTTP

Browsers ignore `Strict-Transport-Security` when it arrives over plain HTTP, so a missing header there is not a meaningful finding. When the **final** URL is `http://`, the HSTS result is `SKIP` with an explanation, and it never contributes to a FAIL exit code. If you request `http://example.com` and it redirects to `https://example.com`, the HTTPS final response is the one evaluated, so HSTS is checked.

### Why `X-Frame-Options` can PASS without the header

`X-Frame-Options` is the older mechanism. CSP `frame-ancestors` is its modern replacement and browsers give it precedence. A site that sets `frame-ancestors 'none'` or `'self'` is not flagged just because `X-Frame-Options` is absent. A `frame-ancestors *` (or scheme-only) value is not treated as protection.

### Deliberate refinement of the CSP rule

The CSP WARN looks at the script directive (`script-src`, falling back to `default-src`) rather than any occurrence of `unsafe-inline`. `'unsafe-inline'` in `style-src` is common and much less severe, and browsers ignore `'unsafe-inline'` in a script directive when a nonce, hash or `'strict-dynamic'` is present. Flagging those cases would create false positives.

## Output

### Human-readable

```
# HTTP Security Header Checker

Requested URL: ...
Final URL: ...
Status: 200
Redirects: 0 (none)

## Security Headers

[PASS] X-Content-Type-Options
       value:  nosniff
       reason: Value is nosniff.
...
## Summary

PASS: 2
WARN: 2
FAIL: 1
SKIP: 1
```

Values are shortened to 120 characters in this view and non-ASCII or control characters are shown as `?` so server-supplied text cannot disturb your terminal. JSON keeps the full values.

### JSON

`--json` prints exactly one JSON document:

| Field | Meaning |
| --- | --- |
| `tool` | Name and version |
| `target` | The URL you asked for |
| `final_url` | URL of the final response after redirects |
| `status_code` | HTTP status of the final response |
| `redirects` / `redirected` | Number of redirects followed / whether any occurred |
| `headers_checked` | Always 6 |
| `summary` | Counts: `pass`, `warn`, `fail`, `skip` |
| `results` | One object per header: `header`, `status`, `value` (`null` if absent), `message` |
| `notes` | Context, e.g. "only the final response was checked", or that the final status was 4xx/5xx |

If the scan cannot complete, `--json` prints `{"target": ..., "error": {"type": ..., "message": ...}}` and exits 2. Error types: `invalid_url`, `dns_error`, `connection_error`, `timeout`, `tls_error`, `too_many_redirects`, `request_error`.

**SAMPLE OUTPUT** is in [`sample-output/`](sample-output/). It was produced by this tool against a local demonstration server (`tests/demo_server.py`) with headers chosen on purpose. It is **not** a scan of a real website and says nothing about any real site. You can regenerate it yourself (see Testing).

## CI Usage

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed, no FAIL results (WARN and SKIP do not fail the run) |
| `1` | Scan completed, one or more FAIL results (or WARN results with `--fail-on-warn`) |
| `2` | Invalid usage, or the scan could not complete (bad URL, DNS, connection, timeout, TLS, ...) |

Generic shell example:

```sh
python scanner.py https://your-own-site.example --json --output header-report.json
status=$?
if [ "$status" -eq 2 ]; then echo "scan error"; fi
exit $status
```

Example GitHub Actions job that checks **a site you own** (replace the URL; no secrets are used). This is an example, not the repository's own workflow, so it is not enabled here:

```yaml
jobs:
  header-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { repository: YOUR-USER/security-header-checker, path: tool }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r tool/requirements.txt
      - run: python tool/scanner.py https://your-own-site.example --json --output header-report.json
      - if: always()
        uses: actions/upload-artifact@v4
        with: { name: header-report, path: header-report.json }
```

The repository's own workflow, [`.github/workflows/tests.yml`](.github/workflows/tests.yml), only installs dependencies and runs the unit tests on Python 3.9 and 3.12. It never scans any website.

## Testing

The tests use a throw-away HTTP server on `127.0.0.1` and `unittest.mock`. None of them contacts an external website.

```
python -m unittest discover -s tests -v
```

They cover: all headers valid; missing headers; weak, malformed and edge-case values for every header; HSTS on HTTP vs HTTPS; `frame-ancestors`; redirects (including loops); 404/500 responses; timeouts; connection refusal; DNS and TLS error handling (mocked); JSON structure and validity; exit codes; CLI help and argument errors; console-safety of output.

To reproduce the sample output locally:

```
python tests/demo_server.py
python scanner.py http://127.0.0.1:8080/
```

(Run the first command in one terminal and the second in another.)

## Real-Input Evaluation

AgenticX asks for a low false-positive rate **measured on real input**. This repository does **not** contain that measurement. You have to collect it yourself on sites you are authorised to inspect, using the procedure below. Do not fill in the table with estimates.

### Definitions

- **Finding** = one result with status `WARN` or `FAIL`. `PASS` and `SKIP` are not findings.
- **Correct finding** = on manual review of the raw final response, the tool's statement is accurate under the rules in this README.
- **False positive (tool error)** = the tool's statement is wrong under its own rules (for example it reports a header missing that is present, or misreads a value).
- **Not actionable** (record separately) = the statement is technically accurate but the site owner has a legitimate reason it does not matter. Count these separately so the numbers are not mixed.

```
false-positive rate = false positives / total reported findings x 100
```

Report the rate for tool errors, and, if you want to be transparent, a second rate that also includes "not actionable". Always state the number of sites and findings next to the percentage. A small sample gives only a rough estimate. This metric also says nothing about issues the tool **missed** (false negatives).

### Procedure

1. Pick a small set of sites you own or have written permission to test. Write them down.
2. Scan each and save the JSON:
   ```
   mkdir results
   python scanner.py https://YOUR-SITE --json --output results\site1.json
   ```
3. Independently capture the raw headers of the same final response, for example with `curl.exe -s -D - -o NUL -L https://YOUR-SITE` (Windows) or the browser DevTools Network tab. The last header block is the final response.
4. For every WARN/FAIL in the JSON, compare it to the raw headers and the rules above, and classify it as correct, false positive (tool error) or not actionable. Note why.
5. Fill in the tables below and compute the rate.

### Table template (TEMPLATE - NOT REAL DATA - fill in your own results)

Per finding:

| Site | Header | Tool status | Raw header value seen | Judgement (correct / false positive / not actionable) | Reason |
| --- | --- | --- | --- | --- | --- |
| _(your data)_ | | | | | |

Per site:

| Site | Date scanned | Total findings | Correct | False positives (tool error) | Not actionable |
| --- | --- | --- | --- | --- | --- |
| _(your data)_ | | | | | |
| **Total** | | | | | |

| Result | Value |
| --- | --- |
| Sites reviewed | _(fill in)_ |
| Total findings | _(fill in)_ |
| False positives (tool error) | _(fill in)_ |
| False-positive rate (tool error) | _(fill in: FP / total x 100)_ |
| Rate including "not actionable" | _(optional)_ |

## Limitations

This tool is deliberately narrow. Be honest about what it is:

- It **only checks HTTP response headers** of one request's final response.
- It **does not prove the application is secure**. A PASS means only that the simplified rule was met.
- It **does not perform penetration testing** and sends no attack traffic.
- It **does not analyse application code**.
- It **does not test whether a CSP actually prevents XSS**. A CSP such as `default-src *` or one containing only `frame-ancestors` still gets PASS, because only simple properties are checked.
- It **does not verify every configuration issue**: it does not check HSTS `max-age` length, `includeSubDomains`/`preload`, other CSP directives, cookie flags, CORS, TLS configuration, `Cross-Origin-*` headers, or any header outside the six listed.
- It **may not understand application-specific security requirements**. For example, a site that intentionally allows framing may legitimately FAIL `X-Frame-Options`.
- It uses **simplified rules**, and **WARN results require human review**.
- Only the **final response after redirects** is checked. Headers on intermediate redirect responses are ignored, and other pages of the same site may send different headers (one URL is checked, not a whole site).
- A request is a plain `GET` with a tool user-agent. Servers, CDNs and WAFs may return different headers to other clients, and error pages (4xx/5xx) often differ from normal pages; the tool notes when the final status is 4xx/5xx.
- Duplicate headers joined by commas (multiple CSPs, for instance) are treated as one value. `script-src-elem`, `script-src-attr` and nested policy details are not evaluated.
- `Permissions-Policy` parsing is simplified; unusual but valid syntax may be reported as WARN, and the legacy `Feature-Policy` header is not read.
- HSTS is not evaluated for plain-HTTP final URLs, and the tool does not check whether a host is on a preload list.
- The false-positive rate in this README is **not** pre-measured; you must measure it on your own real input.

## Ethical Use

Only use this tool against websites and systems you own or have explicit permission to assess. It sends a single ordinary GET request per scan, but you are responsible for how and where you use it.

## Project Structure

```
security-header-checker/
├── scanner.py                 # the tool (CLI, rules, output)
├── requirements.txt           # requests
├── README.md
├── LICENSE                    # MIT
├── .gitignore
├── tests/
│   ├── test_scanner.py        # automated tests (local server + mocks)
│   └── demo_server.py         # local demo server used to reproduce sample output
├── sample-output/
│   ├── sample.txt             # SAMPLE OUTPUT from the local demo server
│   └── sample.json            # same, JSON
└── .github/
    └── workflows/
        └── tests.yml          # runs the unit tests only
```

## License

MIT. See [LICENSE](LICENSE). Replace `<YOUR NAME>` in the license file before publishing.
