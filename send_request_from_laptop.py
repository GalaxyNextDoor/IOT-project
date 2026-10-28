"""
Client Test Script for Laptop-to-Raspberry Pi Demonstration.

Run this script on your laptop to send sample requests to your Raspberry Pi running
the Zero-Trust IoT Platform.

Usage:
    python send_request_from_laptop.py --host <RASPBERRY_PI_IP> --port 8000
    or
    python send_request_from_laptop.py (prompts or uses default)
"""
import sys
import json
import argparse
import urllib.request
import urllib.error

def print_banner():
    print("=" * 70)
    print(" 📡 LAPTOP -> RASPBERRY PI ZERO-TRUST REQUEST SENDER")
    print("=" * 70)

def send_http_request(url: str, method: str = "GET", headers: dict = None, body: dict = None):
    headers = headers or {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    
    print(f"\n📤 Sending {method} to: {url}")
    if headers:
        print(f"   Headers: {headers}")
    if body:
        print(f"   Body   : {json.dumps(body, indent=2)}")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status_code = response.getcode()
            resp_body = response.read().decode("utf-8")
            print(f"\n📥 Response from Raspberry Pi [{status_code}]:")
            try:
                print(json.dumps(json.loads(resp_body), indent=2))
            except Exception:
                print(resp_body)
            return status_code, resp_body
    except urllib.error.HTTPError as e:
        status_code = e.code
        err_body = e.read().decode("utf-8")
        print(f"\n📥 Response from Raspberry Pi [{status_code} - HTTP Error]:")
        try:
            print(json.dumps(json.loads(err_body), indent=2))
        except Exception:
            print(err_body)
        return status_code, err_body
    except Exception as e:
        print(f"\n❌ Failed to connect: {e}")
        print("   -> Make sure the Raspberry Pi is reachable on your Wi-Fi/LAN.")
        print("   -> Make sure the server on Raspberry Pi was started with: uvicorn app.main:app --host 0.0.0.0 --port 8000")
        return None, None

def main():
    parser = argparse.ArgumentParser(description="Send demo requests to Raspberry Pi")
    parser.add_argument("--host", default=None, help="Raspberry Pi IP address (e.g. 192.168.1.50)")
    parser.add_argument("--port", default=8000, type=int, help="Server port (default: 8000)")
    args = parser.parse_args()

    print_banner()

    rpi_host = args.host
    if not rpi_host:
        rpi_host = input("Enter Raspberry Pi IP address [default: 127.0.0.1]: ").strip()
        if not rpi_host:
            rpi_host = "127.0.0.1"

    base_url = f"http://{rpi_host}:{args.port}"
    print(f"\n🎯 Target Server: {base_url}\n")

    api_key_stored = None
    device_id = "RPI-DEMO-LAPTOP-01"

    while True:
        print("-" * 70)
        print("Choose an action to test live on your Raspberry Pi screen:")
        print(" 1. Send Health Check (GET /health)")
        print(" 2. Register Device (POST /api/v1/devices/register)")
        print(" 3. Authenticate Device (POST /api/v1/devices/authenticate)")
        print(" 4. Send Normal Sensor Telemetry (POST /api/v1/telemetry)")
        print(" 5. Send Anomalous / High-Risk Telemetry (triggers Zero-Trust quarantine)")
        print(" 6. Send Unauthorized Request (Invalid API key - triggers DENIAL)")
        print(" 7. Change Raspberry Pi IP")
        print(" 8. Exit")
        choice = input("\nSelect an option [1-8]: ").strip()

        if choice == "1":
            send_http_request(f"{base_url}/health", method="GET")

        elif choice == "2":
            payload = {
                "device_id": device_id,
                "name": "Laptop Remote Node",
                "device_type": "client_node",
                "manufacturer": "Dell/Lenovo/Apple",
                "firmware_version": "2.0.0",
                "ip_address": "192.168.1.150",
                "mac_address": "AA:BB:CC:11:22:33"
            }
            code, resp = send_http_request(
                f"{base_url}/api/v1/devices/register",
                method="POST",
                body=payload
            )
            if code == 200 and resp:
                try:
                    data = json.loads(resp)
                    api_key_stored = data.get("api_key")
                    print(f"\n💡 Saved registered API Key: {api_key_stored}")
                except Exception:
                    pass

        elif choice == "3":
            key_to_use = api_key_stored or input("Enter API Key (or press Enter if registered above): ").strip()
            headers = {
                "X-Device-ID": device_id,
                "X-API-Key": key_to_use
            }
            send_http_request(
                f"{base_url}/api/v1/devices/authenticate",
                method="POST",
                headers=headers
            )

        elif choice == "4":
            key_to_use = api_key_stored or input("Enter API Key: ").strip()
            headers = {
                "X-Device-ID": device_id,
                "X-API-Key": key_to_use
            }
            payload = {
                "device_id": device_id,
                "data_type": "temperature_vibration",
                "metrics": {"temperature": 24.5, "vibration_hz": 12.0, "status": "nominal"},
                "is_anomalous": False
            }
            send_http_request(
                f"{base_url}/api/v1/telemetry",
                method="POST",
                headers=headers,
                body=payload
            )

        elif choice == "5":
            key_to_use = api_key_stored or input("Enter API Key: ").strip()
            headers = {
                "X-Device-ID": device_id,
                "X-API-Key": key_to_use
            }
            payload = {
                "device_id": device_id,
                "data_type": "temperature_vibration",
                "metrics": {"temperature": 189.9, "vibration_hz": 999.0, "anomaly_flag": "CRITICAL_SPIKE"},
                "is_anomalous": True
            }
            send_http_request(
                f"{base_url}/api/v1/telemetry",
                method="POST",
                headers=headers,
                body=payload
            )

        elif choice == "6":
            headers = {
                "X-Device-ID": device_id,
                "X-API-Key": "INVALID_TAMPERED_KEY_XYZ_999"
            }
            send_http_request(
                f"{base_url}/api/v1/devices/authenticate",
                method="POST",
                headers=headers
            )

        elif choice == "7":
            rpi_host = input("Enter new Raspberry Pi IP address: ").strip()
            base_url = f"http://{rpi_host}:{args.port}"
            print(f"Target updated to: {base_url}")

        elif choice == "8":
            print("\nExiting. Have a great demo!")
            break
        else:
            print("Invalid option. Please choose between 1 and 8.")

if __name__ == "__main__":
    main()
