"""
FastAPI Main Application Entry Point with Demonstration Live Request/Response Terminal Middleware.
Zero-Trust IoT Security Platform
"""
import time
import json
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import settings
from app.database import engine, Base
from app.routers import devices, telemetry, risk

# Initialize Database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="IoT Zero-Trust Security Platform",
    description="Zero-Trust Architecture & Dynamic Risk Evaluation Engine for IoT Devices",
    version="1.0.0",
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ANSI Color Codes for Terminal Demonstration
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


class DemonstrationLoggerMiddleware(BaseHTTPMiddleware):
    """
    Middleware to intercept and display full request & response details
    in the server terminal for real-time live demonstration.
    """

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        client_host = request.client.host if request.client else "Unknown IP"
        client_port = request.client.port if request.client else ""
        method = request.method
        url_path = request.url.path

        # Intercept and read request body if JSON/text
        req_body_str = ""
        try:
            req_body_bytes = await request.body()
            if req_body_bytes:
                try:
                    req_body_json = json.loads(req_body_bytes.decode("utf-8"))
                    req_body_str = json.dumps(req_body_json, indent=2)
                except Exception:
                    req_body_str = req_body_bytes.decode("utf-8", errors="replace")

            # Re-wrap body stream so downstream request handlers can read it again
            async def receive():
                return {"type": "http.request", "body": req_body_bytes}

            request._receive = receive
        except Exception as e:
            req_body_str = f"<Unable to read body: {e}>"

        # Headers of interest for IoT Zero-Trust
        device_id = request.headers.get("x-device-id", "N/A")
        api_key_header = request.headers.get("x-api-key", "N/A")
        if api_key_header != "N/A" and len(api_key_header) > 8:
            masked_api_key = api_key_header[:6] + "..." + api_key_header[-2:]
        else:
            masked_api_key = api_key_header

        # Print Incoming Request Banner
        print(f"\n{BOLD}{CYAN}╔════════════════════════════════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{CYAN}║ 📥 INCOMING REQUEST: [{client_host}:{client_port}] ➔ [Server]                     ║{RESET}")
        print(f"{CYAN}╠════════════════════════════════════════════════════════════════════════════════════════╣{RESET}")
        print(f"  {BOLD}Method / Path:{RESET} {GREEN}{method} {url_path}{RESET}")
        print(f"  {BOLD}Device Identification:{RESET} Device-ID: {MAGENTA}{device_id}{RESET} | API Key: {MAGENTA}{masked_api_key}{RESET}")
        if req_body_str:
            print(f"  {BOLD}Payload / Data Sent:{RESET}\n{req_body_str}")
        print(f"{CYAN}────────────────────────────────────────────────────────────────────────────────────────{RESET}")

        # Process the request
        try:
            response = await call_next(request)
        except Exception as exc:
            process_time = (time.time() - start_time) * 1000
            print(f"  {BOLD}{RED}💥 UNHANDLED EXCEPTION ({process_time:.2f}ms): {exc}{RESET}")
            print(f"{BOLD}{RED}╚════════════════════════════════════════════════════════════════════════════════════════╝{RESET}\n")
            raise exc

        process_time = (time.time() - start_time) * 1000

        # Read response body for demonstration logging
        res_body_str = ""
        response_body = b""
        try:
            async for chunk in response.body_iterator:
                response_body += chunk
            
            # Reconstruct response so client receives it
            response = Response(
                content=response_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

            if response_body:
                try:
                    res_json = json.loads(response_body.decode("utf-8"))
                    res_body_str = json.dumps(res_json, indent=2)
                except Exception:
                    res_body_str = response_body.decode("utf-8", errors="replace")
        except Exception as e:
            res_body_str = f"<Unable to inspect response body: {e}>"

        # Determine status color
        if 200 <= response.status_code < 300:
            status_color = GREEN
            decision = "ALLOW"
        elif response.status_code in (401, 403):
            status_color = RED
            decision = "DENY / QUARANTINE"
        else:
            status_color = YELLOW
            decision = "WARNING"

        # Print Server Response Banner
        print(f"  {BOLD}Zero-Trust Decision:{RESET} {status_color}{BOLD}{decision}{RESET}")
        print(f"  {BOLD}Response Code:{RESET} {status_color}{response.status_code}{RESET} ({process_time:.2f} ms latency)")
        if res_body_str:
            print(f"  {BOLD}Response Payload Sent back to [{client_host}]:{RESET}\n{res_body_str}")
        print(f"{BOLD}{CYAN}╚════════════════════════════════════════════════════════════════════════════════════════╝{RESET}\n")

        return response


# Register Demonstration Logger Middleware
app.add_middleware(DemonstrationLoggerMiddleware)

# Include API Routers
app.include_router(devices.router)
app.include_router(telemetry.router)
app.include_router(risk.router)


@app.get("/")
async def root():
    return {
        "status": "online",
        "system": "IoT Zero-Trust Security Platform API",
        "version": "1.0.0",
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
