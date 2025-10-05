#!/usr/bin/env python3
"""
Device Authorization Flow example using Keycloak OIDC provider.

This script demonstrates a standalone Device Flow authentication
using authlib. Device Flow is useful for devices with limited input capabilities
(e.g., smart TVs, IoT devices, CLI tools).

Requirements:
    pip install authlib requests

Configuration:
    Set the following environment variables or modify the constants below:
    - CLIENT_ID: Your Keycloak client ID
    - CLIENT_SECRET: Your Keycloak client secret (optional for public clients)
"""

import os
import sys
import time
import requests
from authlib.integrations.requests_client import OAuth2Session

# Keycloak OIDC Configuration
ISSUER = "http://localhost:18080/realms/myrealm"
DEVICE_AUTHORIZATION_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth/device"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
USERINFO_ENDPOINT = f"{ISSUER}/protocol/openid-connect/userinfo"

# Client Configuration
CLIENT_ID = os.getenv("CLIENT_ID", "oauth2-proxy-device")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")  # Optional for public clients
SCOPE = "openid profile email"


def request_device_code():
    """Request device code from authorization server"""
    data = {
        "client_id": CLIENT_ID,
        "scope": SCOPE
    }

    if CLIENT_SECRET:
        data["client_secret"] = CLIENT_SECRET

    response = requests.post(DEVICE_AUTHORIZATION_ENDPOINT, data=data)

    if response.status_code != 200:
        raise Exception(f"Failed to get device code: {response.status_code} {response.text}")

    return response.json()


def poll_for_token(device_code, interval=5):
    """Poll token endpoint until user completes authorization"""
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": device_code
    }

    if CLIENT_SECRET:
        data["client_secret"] = CLIENT_SECRET

    while True:
        response = requests.post(TOKEN_ENDPOINT, data=data)

        if response.status_code == 200:
            return response.json()

        result = response.json()
        error = result.get("error")

        if error == "authorization_pending":
            # User hasn't completed authorization yet
            print(".", end="", flush=True)
            time.sleep(interval)
        elif error == "slow_down":
            # Server asks us to slow down polling
            interval += 5
            print("!", end="", flush=True)
            time.sleep(interval)
        elif error == "expired_token":
            raise Exception("Device code has expired. Please try again.")
        elif error == "access_denied":
            raise Exception("User denied the authorization request.")
        else:
            raise Exception(f"Error polling for token: {error} - {result.get('error_description', '')}")


def main():
    print("=" * 60)
    print("OIDC Device Authorization Flow Example")
    print("=" * 60)
    print(f"Issuer: {ISSUER}")
    print(f"Client ID: {CLIENT_ID}")
    print("=" * 60)
    print()

    # Step 1: Request device code
    print("Step 1: Requesting device code...")
    device_response = request_device_code()

    device_code = device_response["device_code"]
    user_code = device_response["user_code"]
    verification_uri = device_response["verification_uri"]
    verification_uri_complete = device_response.get("verification_uri_complete")
    expires_in = device_response["expires_in"]
    interval = device_response.get("interval", 5)

    print("✓ Device code received!")
    print()

    # Step 2: Display user instructions
    print("=" * 60)
    print("PLEASE COMPLETE AUTHORIZATION:")
    print("=" * 60)
    print()
    print(f"1. Open this URL in your browser:")
    print(f"   {verification_uri}")
    print()
    print(f"2. Enter this code:")
    print(f"   {user_code}")
    print()

    if verification_uri_complete:
        print("Or use this direct link (includes code):")
        print(f"   {verification_uri_complete}")
        print()

    print(f"Code expires in: {expires_in} seconds")
    print("=" * 60)
    print()

    # Step 3: Poll for token
    print("Step 3: Waiting for authorization", end="", flush=True)

    try:
        token_response = poll_for_token(device_code, interval)
        print()  # New line after polling dots
        print()
        print("✓ Authorization successful!")
        print()

        # Display token information
        access_token = token_response["access_token"]
        token_type = token_response.get("token_type", "Bearer")
        expires_in = token_response.get("expires_in")
        refresh_token = token_response.get("refresh_token")
        id_token = token_response.get("id_token")

        print("Access Token:")
        print(f"  {access_token}")
        print()

        if id_token:
            print("ID Token:")
            print(f"  {id_token}")
            print()

        if refresh_token:
            print("Refresh Token:")
            print(f"  {refresh_token}")
            print()

        print(f"Token Type: {token_type}")
        print(f"Expires In: {expires_in} seconds")
        print()

        # Step 4: Fetch user info
        print("Step 4: Fetching user information...")
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get(USERINFO_ENDPOINT, headers=headers)

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
        print("Device flow completed successfully!")
        print("=" * 60)
        print()

        # Token refresh loop
        if refresh_token:
            print("Step 5: Starting token refresh loop...")
            print("Press Ctrl+C to stop")
            print()

            refresh_count = 0
            current_refresh_token = refresh_token
            current_access_token = access_token
            current_expires_in = expires_in

            while True:
                # Refresh 30 seconds before expiry
                sleep_time = max(current_expires_in - 30, 10)

                print(f"[{time.strftime('%H:%M:%S')}] Token expires in {current_expires_in}s. Sleeping for {sleep_time}s...")
                time.sleep(sleep_time)

                # Refresh token
                print(f"[{time.strftime('%H:%M:%S')}] Refreshing token...")
                try:
                    refresh_data = {
                        "grant_type": "refresh_token",
                        "client_id": CLIENT_ID,
                        "refresh_token": current_refresh_token
                    }
                    if CLIENT_SECRET:
                        refresh_data["client_secret"] = CLIENT_SECRET

                    resp = requests.post(TOKEN_ENDPOINT, data=refresh_data)
                    if resp.status_code == 200:
                        new_token = resp.json()
                        current_access_token = new_token["access_token"]
                        current_refresh_token = new_token.get("refresh_token", current_refresh_token)
                        current_expires_in = new_token.get("expires_in", 300)
                        refresh_count += 1
                        print(f"[{time.strftime('%H:%M:%S')}] ✓ Token refreshed successfully! (Count: {refresh_count})")
                        print(f"  New Access Token: {current_access_token}")
                        print(f"  Expires In: {current_expires_in} seconds")
                        print()
                    else:
                        print(f"[{time.strftime('%H:%M:%S')}] ✗ Failed to refresh token: {resp.status_code} {resp.text}")
                        break
                except Exception as e:
                    print(f"[{time.strftime('%H:%M:%S')}] ✗ Failed to refresh token: {e}")
                    break

        return 0

    except Exception as e:
        print()
        print()
        print(f"✗ Error: {e}")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nDevice flow cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
