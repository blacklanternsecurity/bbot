"""
End-to-end tests that install bbot into a fresh virtualenv and run real CLI scans.

Tests:
    1. Install from local source into a temp venv
    2. DNS-only scan against a real public target
    3. Web scan against a local HTTP server (exercises http + excavate)
"""

import json
import subprocess
import sys
import os
import socket
import textwrap
import time
from pathlib import Path

import pytest


def _find_repo_root():
    """Find the bbot repo root from the source tree, without requiring git."""
    # Walk up from this test file to find pyproject.toml
    d = Path(__file__).resolve().parent
    for _ in range(10):
        if (d / "pyproject.toml").is_file():
            return str(d)
        d = d.parent
    raise FileNotFoundError("could not locate repo root (no pyproject.toml found)")


@pytest.fixture(scope="module")
def bbot_venv(tmp_path_factory):
    """Create a fresh virtualenv and pip-install bbot from the local checkout."""
    venv_dir = tmp_path_factory.mktemp("bbot_e2e_venv")
    repo_root = _find_repo_root()

    subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])
    pip = str(venv_dir / "bin" / "pip")
    bbot = str(venv_dir / "bin" / "bbot")

    subprocess.check_call([pip, "install", "-e", repo_root, "--quiet"], timeout=300)
    assert os.path.isfile(bbot), f"bbot CLI not found at {bbot}"
    return bbot


def _free_port():
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def local_webserver(tmp_path):
    """Spawn a local HTTP server with a page that excavate can extract from."""
    port = _free_port()
    webroot = tmp_path / "webroot"
    webroot.mkdir()

    html = textwrap.dedent("""\
        <html>
        <head><title>E2E Test Page</title></head>
        <body>
            <a href="/secondpage.html">Second Page</a>
        </body>
        </html>
    """)
    (webroot / "index.html").write_text(html)
    (webroot / "secondpage.html").write_text("<html><body>second page</body></html>")

    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--directory", str(webroot), "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # wait for server to be ready
    for _ in range(20):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.25)
    else:
        server.kill()
        pytest.fail(f"Local web server failed to start on port {port}")

    yield f"http://127.0.0.1:{port}"

    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()


def run_bbot(bbot_bin, *args, timeout=180):
    """Run the bbot CLI as a real subprocess."""
    return subprocess.run(
        [bbot_bin] + list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestE2E:
    def test_install_and_help(self, bbot_venv):
        """bbot installs from local source and -h works."""
        r = run_bbot(bbot_venv, "-h")
        assert r.returncode == 0, f"bbot -h failed:\n{r.stderr[-2000:]}"
        assert "usage" in (r.stdout + r.stderr).lower()

    def test_scan_dns(self, bbot_venv, tmp_path):
        """DNS-only scan against one.one.one.one resolves and produces expected events."""
        scan_name = "e2e_dns"
        r = run_bbot(
            bbot_venv,
            "-y",
            "-t",
            "one.one.one.one",
            "-n",
            scan_name,
            "-c",
            "dns.minimal=true",
            f"home={tmp_path}",
            "--json",
        )
        assert r.returncode == 0, f"bbot exited {r.returncode}:\n{r.stderr[-2000:]}"

        events = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        types = {e["type"] for e in events}
        assert "DNS_NAME" in types, f"no DNS_NAME events, got types: {types}"

        dns_events = [e for e in events if e["type"] == "DNS_NAME" and e["data"] == "one.one.one.one"]
        assert dns_events, "no DNS_NAME event for one.one.one.one"
        dns_event = dns_events[0]
        assert "in-scope" in dns_event["tags"]
        resolved = set(dns_event.get("resolved_hosts", []))
        assert resolved & {"1.1.1.1", "1.0.0.1"}, f"expected Cloudflare IPs in resolved_hosts, got {resolved}"

        # verify output files
        scan_home = tmp_path / "scans" / scan_name
        for f in ("output.json", "output.txt", "output.csv", "preset.yml", "scan.log"):
            assert (scan_home / f).is_file(), f"{f} not found in scan output"

    def test_scan_web(self, bbot_venv, tmp_path, local_webserver):
        """Web scan against a local server exercises http + excavate."""
        scan_name = "e2e_web"
        r = run_bbot(
            bbot_venv,
            "-y",
            "-t",
            local_webserver,
            "-n",
            scan_name,
            "-p",
            "spider",
            "-c",
            f"home={tmp_path}",
            "--json",
        )
        assert r.returncode == 0, f"bbot exited {r.returncode}:\n{r.stderr[-2000:]}"

        events = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        types = {e["type"] for e in events}

        assert "URL" in types, f"no URL events, got types: {types}"

        url_events = [e for e in events if e["type"] == "URL"]
        urls = [e.get("data_json", {}).get("url", "") for e in url_events]
        assert any("secondpage.html" in u for u in urls), f"excavate+spider didn't find secondpage.html in {urls}"

    def test_clean_shutdown(self, bbot_venv, tmp_path):
        """Scan completes cleanly: no errors, no orphaned processes."""
        import psutil

        r = run_bbot(
            bbot_venv,
            "-y",
            "-t",
            "one.one.one.one",
            "-n",
            "e2e_shutdown",
            "-c",
            "dns.minimal=true",
            f"home={tmp_path}",
        )
        assert r.returncode == 0, f"bbot exited {r.returncode}:\n{r.stderr[-2000:]}"

        # check output.json for clean completion
        output_json = tmp_path / "scans" / "e2e_shutdown" / "output.json"
        assert output_json.is_file(), "output.json not found"
        events = [json.loads(line) for line in output_json.read_text().splitlines() if line.strip()]
        scan_events = [e for e in events if e.get("type") == "SCAN"]
        statuses = [e.get("data_json", {}).get("status") for e in scan_events]
        assert "FINISHED" in statuses, f"scan didn't reach FINISHED status, got: {statuses}"

        # no critical/error messages in stderr
        for line in r.stderr.splitlines():
            assert "[CRIT]" not in line, f"critical error during scan: {line.strip()}"

        # no orphaned bbot processes
        current = psutil.Process()
        children = current.children(recursive=True)
        bbot_orphans = []
        for p in children:
            try:
                name = p.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if name == "bbot":
                bbot_orphans.append(p)
        assert not bbot_orphans, f"orphaned bbot processes after scan: {[(p.pid, p.cmdline()) for p in bbot_orphans]}"
