"""Automated tests for scanner.py.

No test contacts an external website. Network behaviour is tested against a
throw-away HTTP server on 127.0.0.1, or with unittest.mock.

Run from the project root:
    python -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scanner  # noqa: E402

GOOD_HTTPS_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
}


def setUpModule():
    # Make sure local test traffic never goes through a proxy.
    patcher = mock.patch.dict(
        os.environ, {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"}
    )
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


def status_of(result_list, header):
    for result in result_list:
        if result.header == header:
            return result.status
    raise AssertionError(f"{header} not in results")


def result_of(result_list, header):
    return next(r for r in result_list if r.header == header)


def run_cli(*argv):
    """Run scanner.main(argv); return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = scanner.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def run_cli_expect_exit(*argv):
    """For argparse paths that call sys.exit; return (code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            scanner.main(list(argv))
        except SystemExit as exc:
            return exc.code, out.getvalue(), err.getvalue()
    raise AssertionError("expected SystemExit")


# ---------------------------------------------------------------------------
# Local HTTP server
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = self.server.routes.get(self.path)
        if route is None:
            route = {"status": 404, "headers": []}
        if route.get("delay"):
            time.sleep(route["delay"])
        self.send_response(route["status"])
        for name, value in route["headers"]:
            self.send_header(name, value)
        body = b"ok"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class LocalServerTestCase(unittest.TestCase):
    ROUTES = {}

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.daemon_threads = True
        cls.server.routes = cls.ROUTES
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()


# ---------------------------------------------------------------------------
# Rule tests (pure functions, no network)
# ---------------------------------------------------------------------------

class TestAllHeadersValid(unittest.TestCase):
    def test_all_pass_on_https(self):
        results = scanner.evaluate_headers(GOOD_HTTPS_HEADERS, is_https=True)
        self.assertEqual([r.header for r in results], scanner.HEADER_NAMES)
        self.assertEqual({r.status for r in results}, {"PASS"})
        self.assertEqual(scanner.summarize(results),
                         {"pass": 6, "warn": 0, "fail": 0, "skip": 0})

    def test_header_names_are_case_insensitive(self):
        shouting = {k.upper(): v for k, v in GOOD_HTTPS_HEADERS.items()}
        results = scanner.evaluate_headers(shouting, is_https=True)
        self.assertEqual({r.status for r in results}, {"PASS"})
        lowered = {k.lower(): v for k, v in GOOD_HTTPS_HEADERS.items()}
        results = scanner.evaluate_headers(lowered, is_https=True)
        self.assertEqual({r.status for r in results}, {"PASS"})


class TestMissingHeaders(unittest.TestCase):
    def test_everything_missing_on_https(self):
        results = scanner.evaluate_headers({}, is_https=True)
        self.assertEqual({r.status for r in results}, {"FAIL"})
        for r in results:
            self.assertIsNone(r.value)
            self.assertIn("missing recommended security header", r.message)

    def test_missing_wording_never_says_vulnerable(self):
        for r in scanner.evaluate_headers({}, is_https=True):
            self.assertNotIn("vulnerab", r.message.lower())

    def test_hsts_not_failed_on_plain_http(self):
        results = scanner.evaluate_headers({}, is_https=False)
        self.assertEqual(status_of(results, "Strict-Transport-Security"), "SKIP")
        self.assertEqual(scanner.summarize(results)["fail"], 5)

    def test_hsts_header_on_http_is_still_skipped(self):
        results = scanner.evaluate_headers(
            {"Strict-Transport-Security": "max-age=100"}, is_https=False)
        self.assertEqual(status_of(results, "Strict-Transport-Security"), "SKIP")


class TestHSTS(unittest.TestCase):
    def check(self, value, https=True):
        headers = {} if value is None else {"strict-transport-security": value}
        return scanner.check_hsts(headers, https).status

    def test_values(self):
        cases = [
            ("max-age=31536000", "PASS"),
            ("max-age=31536000; includeSubDomains; preload", "PASS"),
            ("Max-Age=100", "PASS"),
            ('max-age="100"', "PASS"),
            ("includeSubDomains", "WARN"),
            ("max-age=", "WARN"),
            ("max-age=abc", "WARN"),
            ("max-age=-5", "WARN"),
            ("max-age=0", "WARN"),
            ("", "WARN"),
            (None, "FAIL"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(self.check(value), expected)


class TestCSP(unittest.TestCase):
    def check(self, value=None, **extra):
        headers = dict(extra)
        if value is not None:
            headers["content-security-policy"] = value
        return scanner.check_csp(headers)

    def test_present_ok(self):
        self.assertEqual(self.check("default-src 'self'").status, "PASS")

    def test_missing(self):
        self.assertEqual(self.check().status, "FAIL")

    def test_report_only_does_not_count(self):
        result = self.check(**{"content-security-policy-report-only": "default-src 'self'"})
        self.assertEqual(result.status, "FAIL")
        self.assertIn("Report-Only", result.message)

    def test_empty_is_warn(self):
        self.assertEqual(self.check("   ").status, "WARN")

    def test_unsafe_inline_in_script_src_warns(self):
        self.assertEqual(self.check("script-src 'self' 'unsafe-inline'").status, "WARN")

    def test_unsafe_eval_warns(self):
        self.assertEqual(self.check("script-src 'self' 'unsafe-eval'").status, "WARN")

    def test_unsafe_inline_in_default_src_without_script_src_warns(self):
        self.assertEqual(self.check("default-src 'self' 'unsafe-inline'").status, "WARN")

    def test_script_src_overrides_default_src(self):
        self.assertEqual(
            self.check("default-src 'unsafe-inline'; script-src 'self'").status, "PASS")

    def test_unsafe_inline_only_in_style_src_is_not_flagged(self):
        self.assertEqual(
            self.check("default-src 'self'; style-src 'self' 'unsafe-inline'").status, "PASS")

    def test_unsafe_inline_with_nonce_is_not_flagged(self):
        self.assertEqual(
            self.check("script-src 'nonce-abc123' 'unsafe-inline'").status, "PASS")

    def test_unsafe_inline_with_strict_dynamic_is_not_flagged(self):
        self.assertEqual(
            self.check("script-src 'strict-dynamic' 'unsafe-inline' https:").status, "PASS")

    def test_unsafe_eval_not_neutralised_by_nonce(self):
        self.assertEqual(
            self.check("script-src 'nonce-abc' 'unsafe-eval'").status, "WARN")

    def test_directive_names_case_insensitive(self):
        self.assertEqual(self.check("SCRIPT-SRC 'self' 'UNSAFE-INLINE'").status, "WARN")


class TestXContentTypeOptions(unittest.TestCase):
    def check(self, value):
        headers = {} if value is None else {"x-content-type-options": value}
        return scanner.check_x_content_type_options(headers).status

    def test_values(self):
        for value, expected in [
            ("nosniff", "PASS"), ("NoSniff", "PASS"), (" nosniff ", "PASS"),
            ("nosniff, nosniff", "PASS"),
            ("sniff", "WARN"), ("", "WARN"), ("nosniff-ish", "WARN"),
            (None, "FAIL"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(self.check(value), expected)


class TestXFrameOptions(unittest.TestCase):
    def check(self, xfo=None, csp=None):
        headers = {}
        if xfo is not None:
            headers["x-frame-options"] = xfo
        if csp is not None:
            headers["content-security-policy"] = csp
        return scanner.check_x_frame_options(headers)

    def test_xfo_values(self):
        for value, expected in [
            ("DENY", "PASS"), ("SAMEORIGIN", "PASS"), ("deny", "PASS"),
            ("sameorigin", "PASS"),
            ("ALLOW-FROM https://a.example", "WARN"), ("bogus", "WARN"),
            ("", "WARN"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(self.check(xfo=value).status, expected)

    def test_missing_without_csp_fails(self):
        result = self.check()
        self.assertEqual(result.status, "FAIL")
        self.assertIn("missing recommended security header", result.message)

    def test_frame_ancestors_none_is_accepted(self):
        result = self.check(csp="default-src 'self'; frame-ancestors 'none'")
        self.assertEqual(result.status, "PASS")
        self.assertIn("frame-ancestors", result.message)

    def test_frame_ancestors_self_and_host_accepted(self):
        self.assertEqual(
            self.check(csp="frame-ancestors 'self' https://partner.example").status, "PASS")

    def test_frame_ancestors_wildcard_is_not_protection(self):
        self.assertEqual(self.check(csp="frame-ancestors *").status, "FAIL")

    def test_frame_ancestors_scheme_only_is_not_protection(self):
        self.assertEqual(self.check(csp="frame-ancestors https:").status, "FAIL")

    def test_empty_frame_ancestors_is_not_protection(self):
        self.assertEqual(self.check(csp="frame-ancestors; default-src 'self'").status, "FAIL")

    def test_csp_without_frame_ancestors_fails(self):
        self.assertEqual(self.check(csp="default-src 'self'").status, "FAIL")

    def test_invalid_xfo_with_good_frame_ancestors_passes(self):
        self.assertEqual(self.check(xfo="bogus", csp="frame-ancestors 'self'").status, "PASS")

    def test_invalid_xfo_with_wildcard_frame_ancestors_warns(self):
        self.assertEqual(self.check(xfo="bogus", csp="frame-ancestors *").status, "WARN")


class TestReferrerPolicy(unittest.TestCase):
    def check(self, value):
        headers = {} if value is None else {"referrer-policy": value}
        return scanner.check_referrer_policy(headers).status

    def test_values(self):
        for value, expected in [
            ("no-referrer", "PASS"), ("same-origin", "PASS"),
            ("strict-origin", "PASS"), ("strict-origin-when-cross-origin", "PASS"),
            ("Strict-Origin", "PASS"),
            ("no-referrer, strict-origin-when-cross-origin", "PASS"),
            ("unsafe-url", "WARN"), ("no-referrer-when-downgrade", "WARN"),
            ("origin", "WARN"), ("origin-when-cross-origin", "WARN"),
            ("strict-origin-when-cross-origin, unsafe-url", "WARN"),
            ("unsafe-url, bogus", "WARN"),  # last *recognised* value wins
            ("bogus", "WARN"), ("", "WARN"), (" , ", "WARN"),
            (None, "FAIL"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(self.check(value), expected)


class TestPermissionsPolicy(unittest.TestCase):
    def check(self, value):
        headers = {} if value is None else {"permissions-policy": value}
        return scanner.check_permissions_policy(headers).status

    def test_values(self):
        for value, expected in [
            ("geolocation=(), camera=()", "PASS"),
            ('geolocation=(self "https://a.example"), microphone=()', "PASS"),
            ("camera=*", "PASS"),
            ("interest-cohort=()", "PASS"),
            ("", "WARN"), ("   ", "WARN"),
            ("geolocation=(", "WARN"),
            ("geolocation=)", "WARN"),
            ("garbage", "WARN"),
            ("geolocation=(), ", "WARN"),
            ("geolocation=self", "WARN"),
            ("=()", "WARN"),
            (None, "FAIL"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(self.check(value), expected)

    def test_comma_inside_parentheses_does_not_split(self):
        self.assertEqual(self.check('geolocation=("https://a.example,b")'), "PASS")


class TestSummaryAndExitCodes(unittest.TestCase):
    def report(self, **counts):
        base = {"pass": 0, "warn": 0, "fail": 0, "skip": 0}
        base.update(counts)
        return {"summary": base}

    def test_exit_code_mapping(self):
        self.assertEqual(scanner.exit_code_for(self.report(**{"pass": 6})), 0)
        self.assertEqual(scanner.exit_code_for(self.report(warn=2)), 0)
        self.assertEqual(scanner.exit_code_for(self.report(fail=1)), 1)
        self.assertEqual(scanner.exit_code_for(self.report(warn=1), fail_on_warn=True), 1)
        self.assertEqual(scanner.exit_code_for(self.report(skip=1), fail_on_warn=True), 0)


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------

class TestURLValidation(unittest.TestCase):
    def test_valid(self):
        for url in ["http://example.com", "https://example.com/path?q=1",
                    "https://example.com:8443/", "  https://example.com  "]:
            with self.subTest(url=url):
                self.assertEqual(scanner.validate_url(url), url.strip())

    def test_invalid(self):
        for url in ["example.com", "", "ftp://example.com", "http://", "https:///path",
                    "http://host:99999", "javascript:alert(1)", "example.com:8080"]:
            with self.subTest(url=url):
                with self.assertRaises(scanner.ScanError) as ctx:
                    scanner.validate_url(url)
                self.assertEqual(ctx.exception.error_type, "invalid_url")

    def test_credentials_in_url_rejected(self):
        with self.assertRaises(scanner.ScanError) as ctx:
            scanner.validate_url("https://user:secret@example.com/")
        self.assertNotIn("secret", ctx.exception.message)


# ---------------------------------------------------------------------------
# End-to-end tests against a local HTTP server
# ---------------------------------------------------------------------------

class TestLocalScans(LocalServerTestCase):
    ROUTES = {
        "/good": {"status": 200, "headers": [
            ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
            ("X-CONTENT-TYPE-OPTIONS", "nosniff"),  # odd casing on purpose
            ("X-Frame-Options", "SAMEORIGIN"),
            ("Referrer-Policy", "no-referrer"),
            ("permissions-policy", "geolocation=()"),
        ]},
        "/bare": {"status": 200, "headers": []},
        "/weak": {"status": 200, "headers": [
            ("Content-Security-Policy", "script-src 'unsafe-inline'"),
            ("X-Content-Type-Options", "sniff"),
            ("X-Frame-Options", "bogus"),
            ("Referrer-Policy", "unsafe-url"),
            ("Permissions-Policy", "garbage"),
        ]},
        "/redirect": {"status": 302, "headers": [("Location", "/good")]},
        "/redirect2": {"status": 301, "headers": [("Location", "/redirect")]},
        "/loop": {"status": 302, "headers": [("Location", "/loop")]},
        "/slow": {"status": 200, "headers": [], "delay": 2.0},
        "/teapot": {"status": 500, "headers": [("X-Content-Type-Options", "nosniff")]},
    }

    def test_good_page_has_no_fail_and_exit_0(self):
        code, out, err = run_cli(self.base + "/good", "--json")
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(report["summary"],
                         {"pass": 5, "warn": 0, "fail": 0, "skip": 1})
        by_header = {r["header"]: r["status"] for r in report["results"]}
        self.assertEqual(by_header["Strict-Transport-Security"], "SKIP")

    def test_bare_page_fails_and_exit_1(self):
        code, out, _ = run_cli(self.base + "/bare", "--json")
        report = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"],
                         {"pass": 0, "warn": 0, "fail": 5, "skip": 1})

    def test_weak_page_warns_only(self):
        code, out, _ = run_cli(self.base + "/weak", "--json")
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["warn"], 5)
        self.assertEqual(report["summary"]["fail"], 0)

    def test_fail_on_warn(self):
        code, _, _ = run_cli(self.base + "/weak", "--json", "--fail-on-warn")
        self.assertEqual(code, 1)
        code, _, _ = run_cli(self.base + "/good", "--json", "--fail-on-warn")
        self.assertEqual(code, 0)

    def test_redirect_is_followed_and_recorded(self):
        report = scanner.scan(self.base + "/redirect")
        self.assertEqual(report["target"], self.base + "/redirect")
        self.assertEqual(report["final_url"], self.base + "/good")
        self.assertEqual(report["status_code"], 200)
        self.assertEqual(report["redirects"], 1)
        self.assertTrue(report["redirected"])
        self.assertTrue(any("final response" in n for n in report["notes"]))

    def test_two_redirects_counted(self):
        report = scanner.scan(self.base + "/redirect2")
        self.assertEqual(report["redirects"], 2)
        self.assertEqual(report["final_url"], self.base + "/good")

    def test_no_redirect(self):
        report = scanner.scan(self.base + "/good")
        self.assertEqual(report["redirects"], 0)
        self.assertFalse(report["redirected"])
        self.assertEqual(report["final_url"], self.base + "/good")

    def test_http_error_status_still_reported_with_note(self):
        code, out, _ = run_cli(self.base + "/teapot", "--json")
        report = json.loads(out)
        self.assertEqual(report["status_code"], 500)
        self.assertTrue(any("HTTP 500" in n for n in report["notes"]))
        self.assertEqual(code, 1)  # other headers are missing

    def test_404_is_reported_not_crashed(self):
        code, out, err = run_cli(self.base + "/does-not-exist", "--json")
        self.assertEqual(json.loads(out)["status_code"], 404)
        self.assertNotIn("Traceback", err)

    def test_redirect_loop_is_clean_error(self):
        code, out, err = run_cli(self.base + "/loop", "--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"]["type"], "too_many_redirects")

    def test_timeout_is_clean_error(self):
        code, out, err = run_cli(self.base + "/slow", "--json", "--timeout", "0.3")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"]["type"], "timeout")

    def test_timeout_text_mode_goes_to_stderr(self):
        code, out, err = run_cli(self.base + "/slow", "--timeout", "0.3")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("Timed out", err)
        self.assertNotIn("Traceback", err)

    def test_connection_refused_is_clean_error(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()  # nothing is listening on this port now
        code, out, err = run_cli(f"http://127.0.0.1:{port}/", "--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"]["type"], "connection_error")


# ---------------------------------------------------------------------------
# HTTPS and failure modes via mocks (no network)
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, url, headers, status=200, history=0):
        self.url = url
        self.headers = requests.structures.CaseInsensitiveDict(headers)
        self.status_code = status
        self.history = [object()] * history
        self.closed = False

    def close(self):
        self.closed = True


class TestMockedHTTPS(unittest.TestCase):
    def test_https_target_evaluates_hsts_and_passes(self):
        fake = FakeResponse("https://example.test/", GOOD_HTTPS_HEADERS)
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("https://example.test")
        self.assertEqual(report["summary"], {"pass": 6, "warn": 0, "fail": 0, "skip": 0})
        self.assertTrue(fake.closed)

    def test_https_without_hsts_fails(self):
        headers = {k: v for k, v in GOOD_HTTPS_HEADERS.items()
                   if k != "Strict-Transport-Security"}
        fake = FakeResponse("https://example.test/", headers)
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("https://example.test")
        hsts = next(r for r in report["results"] if r["header"] == "Strict-Transport-Security")
        self.assertEqual(hsts["status"], "FAIL")

    def test_http_to_https_redirect_checks_hsts_on_final_response(self):
        fake = FakeResponse("https://example.test/", GOOD_HTTPS_HEADERS, history=1)
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("http://example.test")
        self.assertEqual(report["redirects"], 1)
        hsts = next(r for r in report["results"] if r["header"] == "Strict-Transport-Security")
        self.assertEqual(hsts["status"], "PASS")

    def test_https_to_http_downgrade_is_noted(self):
        fake = FakeResponse("http://example.test/", {}, history=1)
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("https://example.test")
        self.assertTrue(any("ended on plain HTTP" in n for n in report["notes"]))

    def test_requests_headers_object_is_case_insensitive(self):
        fake = FakeResponse("https://example.test/",
                            {k.lower(): v for k, v in GOOD_HTTPS_HEADERS.items()})
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("https://example.test")
        self.assertEqual(report["summary"]["pass"], 6)


class TestMockedFailures(unittest.TestCase):
    def error_type(self, exc):
        with mock.patch("scanner.requests.Session.get", side_effect=exc):
            code, out, err = run_cli("https://example.test", "--json")
        self.assertEqual(code, 2)
        self.assertEqual(err, "")
        return json.loads(out)["error"]["type"]

    def test_tls_error(self):
        self.assertEqual(self.error_type(requests.exceptions.SSLError("bad cert")), "tls_error")

    def test_dns_errors(self):
        for text in ["NameResolutionError: Failed to resolve 'x'",
                     "[Errno -2] Name or service not known",
                     "[Errno 11001] getaddrinfo failed"]:
            with self.subTest(text=text):
                self.assertEqual(
                    self.error_type(requests.exceptions.ConnectionError(text)), "dns_error")

    def test_connection_error(self):
        self.assertEqual(
            self.error_type(requests.exceptions.ConnectionError("Connection refused")),
            "connection_error")

    def test_connect_timeout(self):
        self.assertEqual(self.error_type(requests.exceptions.ConnectTimeout()), "timeout")

    def test_read_timeout(self):
        self.assertEqual(self.error_type(requests.exceptions.ReadTimeout()), "timeout")

    def test_generic_request_exception(self):
        self.assertEqual(
            self.error_type(requests.exceptions.RequestException("boom")), "request_error")

    def test_invalid_url_exception_from_requests(self):
        self.assertEqual(
            self.error_type(requests.exceptions.InvalidURL("bad")), "invalid_url")

    def test_text_mode_error_has_no_traceback(self):
        with mock.patch("scanner.requests.Session.get",
                        side_effect=requests.exceptions.SSLError("bad cert")):
            code, out, err = run_cli("https://example.test")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("TLS/SSL", err)
        self.assertNotIn("Traceback", err)


# ---------------------------------------------------------------------------
# Output format and CLI behaviour
# ---------------------------------------------------------------------------

class TestOutput(unittest.TestCase):
    def setUp(self):
        fake = FakeResponse("https://example.test/", GOOD_HTTPS_HEADERS, history=1)
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            self.report = scanner.scan("http://example.test")

    def test_json_structure(self):
        code, out, err = None, None, None
        fake = FakeResponse("https://example.test/", GOOD_HTTPS_HEADERS, history=1)
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            code, out, err = run_cli("http://example.test", "--json")
        report = json.loads(out)  # raises if stdout is not pure valid JSON
        self.assertEqual(err, "")
        for key in ["target", "final_url", "status_code", "redirects",
                    "headers_checked", "summary", "results"]:
            self.assertIn(key, report)
        self.assertEqual(report["target"], "http://example.test")
        self.assertEqual(report["final_url"], "https://example.test/")
        self.assertEqual(report["status_code"], 200)
        self.assertEqual(report["redirects"], 1)
        self.assertEqual(report["headers_checked"], 6)
        self.assertEqual(set(report["summary"]), {"pass", "warn", "fail", "skip"})
        self.assertEqual(sum(report["summary"].values()), 6)
        self.assertEqual(len(report["results"]), 6)
        for item in report["results"]:
            self.assertEqual(set(item), {"header", "status", "value", "message"})
            self.assertIn(item["status"], {"PASS", "WARN", "FAIL", "SKIP"})
        self.assertEqual([r["header"] for r in report["results"]], scanner.HEADER_NAMES)

    def test_json_error_document_is_valid(self):
        code, out, err = run_cli("not-a-url", "--json")
        doc = json.loads(out)
        self.assertEqual(code, 2)
        self.assertEqual(doc["target"], "not-a-url")
        self.assertEqual(doc["error"]["type"], "invalid_url")

    def test_text_output_layout(self):
        text = scanner.format_text(self.report)
        for expected in ["# HTTP Security Header Checker", "Requested URL: http://example.test",
                         "Final URL: https://example.test/", "Status: 200",
                         "Redirects: 1 (redirected)", "## Security Headers",
                         "[PASS] Strict-Transport-Security", "## Summary", "PASS: 6",
                         "WARN: 0", "FAIL: 0", "SKIP: 0", "does not mean the site is secure"]:
            self.assertIn(expected, text)

    def test_text_output_never_uses_the_word_vulnerable(self):
        fake = FakeResponse("https://example.test/", {})
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("https://example.test")
        text = scanner.format_text(report).lower()
        self.assertIn("[fail]", text)
        self.assertNotIn("vulnerab", text)

    def test_text_output_strips_control_characters_from_values(self):
        fake = FakeResponse("https://example.test/",
                            {"Referrer-Policy": "no-referrer\x1b[31mRED"})
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("https://example.test")
        self.assertNotIn("\x1b", scanner.format_text(report))

    def test_long_values_are_truncated_in_text_but_not_json(self):
        long_csp = "default-src 'self'; img-src " + "https://a.example " * 40
        fake = FakeResponse("https://example.test/", {"Content-Security-Policy": long_csp})
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("https://example.test")
        self.assertIn("...", scanner.format_text(report))
        csp = next(r for r in report["results"] if r["header"] == "Content-Security-Policy")
        self.assertEqual(csp["value"], long_csp)


class TestCLI(unittest.TestCase):
    def test_help(self):
        code, out, _ = run_cli_expect_exit("--help")
        self.assertEqual(code, 0)
        for expected in ["usage:", "url", "--json", "--timeout", "--fail-on-warn", "exit codes"]:
            self.assertIn(expected, out)

    def test_missing_url_is_usage_error(self):
        code, _, err = run_cli_expect_exit()
        self.assertEqual(code, 2)
        self.assertIn("usage:", err)

    def test_bad_timeout_is_usage_error(self):
        for bad in ["0", "-3", "abc"]:
            with self.subTest(timeout=bad):
                code, _, _ = run_cli_expect_exit("https://example.test", "--timeout", bad)
                self.assertEqual(code, 2)

    def test_invalid_url_text_mode(self):
        code, out, err = run_cli("example.com")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("must start with http:// or https://", err)
        self.assertNotIn("Traceback", err)

    def test_output_file_json_is_utf8_and_stdout_is_empty(self):
        import tempfile
        fake = FakeResponse("https://example.test/", GOOD_HTTPS_HEADERS)
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("scanner.requests.Session.get", return_value=fake):
            path = Path(tmp) / "report.json"
            code, out, err = run_cli("https://example.test", "--json", "--output", str(path))
            self.assertEqual((code, out, err), (0, "", ""))
            raw = path.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))  # no BOM
            self.assertEqual(json.loads(raw.decode("utf-8"))["summary"]["pass"], 6)

    def test_output_file_text_mode(self):
        import tempfile
        fake = FakeResponse("https://example.test/", {})
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("scanner.requests.Session.get", return_value=fake):
            path = Path(tmp) / "report.txt"
            code, out, _ = run_cli("https://example.test", "--output", str(path))
            self.assertEqual((code, out), (1, ""))
            self.assertIn("[FAIL] Content-Security-Policy", path.read_text(encoding="utf-8"))

    def test_unwritable_output_path_is_clean_error(self):
        fake = FakeResponse("https://example.test/", GOOD_HTTPS_HEADERS)
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            code, out, err = run_cli("https://example.test", "--output",
                                     str(Path("/nonexistent-dir-xyz") / "r.json"))
        self.assertEqual(code, 2)
        self.assertIn("could not write", err)
        self.assertNotIn("Traceback", err)

    def test_non_ascii_header_values_are_safe_for_console_text(self):
        fake = FakeResponse("https://example.test/", {"Referrer-Policy": "no-referrer \u00e9\u4e2d"})
        with mock.patch("scanner.requests.Session.get", return_value=fake):
            report = scanner.scan("https://example.test")
        scanner.format_text(report).encode("ascii")  # must not raise
        self.assertIn("\u00e9", json.dumps(report, ensure_ascii=False))
        json.dumps(report).encode("ascii")  # JSON stays ASCII-safe too

    def test_version(self):
        code, out, _ = run_cli_expect_exit("--version")
        self.assertEqual(code, 0)
        self.assertIn(scanner.__version__, out)

    def test_script_runs_as_subprocess_with_exit_code_2_on_bad_url(self):
        import subprocess
        root = Path(__file__).resolve().parents[1]
        proc = subprocess.run([sys.executable, str(root / "scanner.py"), "nope", "--json"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["error"]["type"], "invalid_url")
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main()
