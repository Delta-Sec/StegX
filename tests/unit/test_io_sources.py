
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO

import pytest
from PIL import Image

from stegx.io_sources import (
    MAX_DOWNLOAD_BYTES,
    fetch_cover_to_tempfile,
    is_url,
)

def test_is_url_accepts_http_and_https():
    assert is_url("https://example.com/cover.png")
    assert is_url("http://localhost/cover.png")

def test_is_url_rejects_other_schemes():
    assert not is_url("ftp://example.com/cover.png")
    assert not is_url("file:///etc/passwd")
    assert not is_url("/local/path/cover.png")
    assert not is_url("cover.png")
    assert not is_url("https://")

class _StubHandler(BaseHTTPRequestHandler):
    responses = {}

    def do_GET(self):
        status, headers, body = self.responses.get(self.path, (404, {}, b""))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *a, **k):
        pass

@pytest.fixture
def _allow_loopback(monkeypatch):
    monkeypatch.setattr("stegx.io_sources._is_safe_ip", lambda ip: True)

@pytest.fixture
def local_server(_allow_loopback):
    server = HTTPServer(("127.0.0.1", 0), _StubHandler)
    _StubHandler.responses = {}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}", _StubHandler.responses
    server.shutdown()
    server.server_close()

def _png_bytes(width=30, height=30):
    buf = BytesIO()
    Image.new("RGB", (width, height), (127, 127, 127)).save(buf, "PNG")
    return buf.getvalue()

def test_fetch_valid_png(local_server):
    base, responses = local_server
    responses["/cover.png"] = (200, {"Content-Type": "image/png"}, _png_bytes())

    tmp_path = fetch_cover_to_tempfile(f"{base}/cover.png")
    try:
        assert os.path.isfile(tmp_path)
        with Image.open(tmp_path) as img:
            assert img.mode in ("RGB", "RGBA")
    finally:
        os.unlink(tmp_path)

def test_fetch_rejects_non_image_content_type(local_server):
    base, responses = local_server
    responses["/evil"] = (200, {"Content-Type": "application/octet-stream"}, b"not-an-image")
    with pytest.raises(ValueError, match="non-image"):
        fetch_cover_to_tempfile(f"{base}/evil")

def test_fetch_rejects_malformed_image(local_server):
    base, responses = local_server

    responses["/broken.png"] = (200, {"Content-Type": "image/png"}, b"\x00" * 100)
    with pytest.raises(ValueError):
        fetch_cover_to_tempfile(f"{base}/broken.png")

def test_fetch_rejects_unknown_scheme():
    with pytest.raises(ValueError, match="scheme"):
        fetch_cover_to_tempfile("ftp://example.com/cover.png")

def test_fetch_rejects_missing_host():
    with pytest.raises(ValueError):
        fetch_cover_to_tempfile("http:///no-host")

def test_fetch_404(local_server):
    base, _ = local_server
    with pytest.raises(ValueError):
        fetch_cover_to_tempfile(f"{base}/does-not-exist")

def test_download_cap_constant_is_reasonable():


    assert 1 * 1024 * 1024 <= MAX_DOWNLOAD_BYTES <= 500 * 1024 * 1024
