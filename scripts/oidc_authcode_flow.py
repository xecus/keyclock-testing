#!/usr/bin/env python3
"""
Authorization Code Flow example using Keycloak OIDC provider.

This script demonstrates a standalone Authorization Code Flow authentication
using authlib with a Confidential Client.

Requirements:
    pip install authlib requests

Configuration:
    Set the following environment variables or modify the constants below:
    - CLIENT_ID: Your Keycloak client ID
    - CLIENT_SECRET: Your Keycloak client secret
    - REDIRECT_URI: Callback URL (default: http://localhost:8080/callback)
"""

import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import webbrowser
from authlib.integrations.requests_client import OAuth2Session

# Keycloak OIDC Configuration
ISSUER = "http://localhost:18080/realms/myrealm"
AUTHORIZATION_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
USERINFO_ENDPOINT = f"{ISSUER}/protocol/openid-connect/userinfo"

# Client Configuration (Confidential Client)
CLIENT_ID = os.getenv("CLIENT_ID", "oauth2-proxy")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "your-client-secret")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8080/callback")
SCOPE = "openid profile email"

# Global variable to store authorization code
authorization_code = None
state = None


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth2 callback"""

    def do_GET(self):
        global authorization_code, state

        # Parse the callback URL
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)

        if parsed_url.path == "/callback":
            if "code" in params:
                authorization_code = params["code"][0]
                received_state = params.get("state", [None])[0]

                # Verify state
                if received_state != state:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"State mismatch! Possible CSRF attack.")
                    return

                # Success page
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                    <html>
                    <body>
                        <h1>Authentication Successful!</h1>
                        <p>You can close this window and return to the terminal.</p>
                        <script>window.close();</script>
                    </body>
                    </html>
                """)
            elif "error" in params:
                error = params["error"][0]
                error_description = params.get("error_description", [""])[0]

                self.send_response(400)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(f"""
                    <html>
                    <body>
                        <h1>Authentication Failed</h1>
                        <p>Error: {error}</p>
                        <p>Description: {error_description}</p>
                    </body>
                    </html>
                """.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default logging
        pass


def start_callback_server():
    """Start local HTTP server to receive callback"""
    server_address = ("", 8080)
    httpd = HTTPServer(server_address, CallbackHandler)
    return httpd


def main():
    global authorization_code, state

    print("=" * 60)
    print("OIDC Authorization Code Flow Example")
    print("=" * 60)
    print(f"Issuer: {ISSUER}")
    print(f"Client ID: {CLIENT_ID}")
    print(f"Redirect URI: {REDIRECT_URI}")
    print("=" * 60)
    print()

    # Create OAuth2 session
    client = OAuth2Session(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        scope=SCOPE
    )

    # Generate authorization URL
    uri, state = client.create_authorization_url(AUTHORIZATION_ENDPOINT)

    print("Step 1: Starting local callback server...")
    httpd = start_callback_server()
    print(f"Callback server started at {REDIRECT_URI}")
    print()

    print("Step 2: Opening browser for authentication...")
    print(f"Authorization URL: {uri}")
    print()

    # Open browser for authentication
    webbrowser.open(uri)

    print("Step 3: Waiting for callback...")
    print("Please complete the authentication in your browser.")
    print()

    # Wait for callback
    while authorization_code is None:
        httpd.handle_request()

    httpd.server_close()

    if authorization_code:
        print("Step 4: Exchanging authorization code for tokens...")

        # Exchange authorization code for tokens
        token = client.fetch_token(
            TOKEN_ENDPOINT,
            authorization_response=f"{REDIRECT_URI}?code={authorization_code}&state={state}",
            grant_type="authorization_code"
        )

        print("✓ Tokens received successfully!")
        print()
        print("Access Token:")
        print(f"  {token['access_token']}")
        print()

        if "id_token" in token:
            print("ID Token:")
            print(f"  {token['id_token']}")
            print()

        if "refresh_token" in token:
            print("Refresh Token:")
            print(f"  {token['refresh_token']}")
            print()

        print(f"Token Type: {token.get('token_type')}")
        print(f"Expires In: {token.get('expires_in')} seconds")
        print()

        # Fetch user info
        print("Step 5: Fetching user information...")
        resp = client.get(USERINFO_ENDPOINT)

        if resp.status_code == 200:
            userinfo = resp.json()
            print("✓ User information retrieved successfully!")
            print()
            print("User Info:")
            for key, value in userinfo.items():
                print(f"  {key}: {value}")
        else:
            print(f"✗ Failed to fetch user info: {resp.status_code}")
            print(f"  {resp.text}")

        print()
        print("=" * 60)
        print("Authentication flow completed successfully!")
        print("=" * 60)
        print()

        # Token refresh loop
        if "refresh_token" in token:
            print("Step 6: Starting token refresh loop...")
            print("Press Ctrl+C to stop")
            print()

            refresh_count = 0
            while True:
                expires_in = token.get('expires_in', 300)
                # Refresh 30 seconds before expiry
                sleep_time = max(expires_in - 30, 10)

                print(f"[{time.strftime('%H:%M:%S')}] Token expires in {expires_in}s. Sleeping for {sleep_time}s...")
                time.sleep(sleep_time)

                # Refresh token
                print(f"[{time.strftime('%H:%M:%S')}] Refreshing token...")
                try:
                    token = client.refresh_token(
                        TOKEN_ENDPOINT,
                        refresh_token=token['refresh_token']
                    )
                    refresh_count += 1
                    print(f"[{time.strftime('%H:%M:%S')}] ✓ Token refreshed successfully! (Count: {refresh_count})")
                    print(f"  New Access Token: {token['access_token']}")
                    print(f"  Expires In: {token.get('expires_in')} seconds")
                    print()
                except Exception as e:
                    print(f"[{time.strftime('%H:%M:%S')}] ✗ Failed to refresh token: {e}")
                    break

        return 0
    else:
        print("✗ Authentication failed or was cancelled.")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nAuthentication cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
