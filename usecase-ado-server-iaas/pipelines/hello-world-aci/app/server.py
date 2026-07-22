#!/usr/bin/env python3
"""Minimal dependency-free hello-world HTTP server for Confidential ACI.

Serves a single page on port 8080 that confirms the container is running and
echoes a few environment facts (hostname, SKU) so a viewer can see it is
executing inside an AMD SEV-SNP Confidential Container Instance.
"""
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
ACI_SKU = os.environ.get("ACI_SKU", "unknown")

PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Hello from Confidential ACI</title>
<style>
 body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:3rem auto;max-width:40rem;line-height:1.5}}
 code{{background:#f2f2f2;padding:.1rem .35rem;border-radius:.25rem}}
 .sku{{font-weight:600;color:#0a7d28}}
</style></head>
<body>
 <h1>Hello, world!</h1>
 <p>This page is served by a container running on an Azure Container Instance.</p>
 <ul>
  <li>Hostname: <code>{host}</code></li>
  <li>ACI SKU: <span class="sku">{sku}</span></li>
 </ul>
 <p>Built and deployed by the <code>confidential-build-pool</code> Azure DevOps
    pipeline onto AMD SEV-SNP confidential hardware.</p>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, content_type="text/html; charset=utf-8"):
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, "ok", "text/plain; charset=utf-8")
            return
        self._send(200, PAGE.format(host=socket.gethostname(), sku=ACI_SKU))

    def log_message(self, fmt, *args):
        # Keep stdout quiet/structured; ACI captures it for non-confidential SKUs.
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"hello-world server listening on :{PORT} (sku={ACI_SKU})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
