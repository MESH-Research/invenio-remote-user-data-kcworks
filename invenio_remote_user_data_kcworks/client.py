# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Functions and classes for interacting with the IDMS API."""

import os

import requests
from flask import current_app as app
from flask import request
from .types import APIResponse, LogoutRequest, Profile


class SessionBrokerAPIClient:
    """Client for interacting with the Profiles session broker."""

    @staticmethod
    def silent_login_check(
        cookies: dict,
        *,
        return_to: str,
        final_redirect: str,
    ) -> dict | None:
        """Perform a server-side silent login check against the Profiles broker.

        Forwards the user's session cookie so the Profiles microservice can
        determine whether an active session exists.

        Args:
            cookies: A dict of cookies from the incoming request. The relevant
                session cookie will be extracted based on config.
            return_to: The KCWorks callback URL used for the explicit login flow.
            final_redirect: The URL KCWorks should ultimately redirect to.

        Returns:
            The JSON response dict if an active session was found (contains
            ``broker_token``), or None if there is no session or the request
            fails.
        """
        silent_url = app.config.get("SSO_BROKER_SILENT_LOGIN_URL")
        if not silent_url:
            app.logger.error("SSO_BROKER_SILENT_LOGIN_URL not configured")
            return None

        bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")
        if not bearer_token:
            app.logger.error("COMMONS_PROFILES_API_TOKEN not set")
            return None

        cookie_name = app.config.get("SSO_BROKER_RETRY_COOKIE_NAME")
        forwarded_cookies = {}
        if cookie_name and cookie_name in cookies:
            forwarded_cookies[cookie_name] = cookies[cookie_name]

        timeout = app.config.get("SSO_BROKER_SILENT_LOGIN_TIMEOUT", 3)
        try:
            resp = requests.get(
                silent_url,
                headers={
                    "Authorization": f"Bearer {bearer_token}",
                },
                cookies=forwarded_cookies,
                params={
                    "return_to": return_to,
                    "final_redirect": final_redirect,
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("no_session") or "broker_token" not in data:
                return None
            return data
        except Exception:
            app.logger.exception("Silent login check failed")
            return None

    @staticmethod
    def verify_nonce(nonce: str) -> bool:
        """Validate a broker nonce against the Profiles microservice.

        Args:
            nonce: The nonce string from the decrypted broker token.

        Returns:
            True if the nonce is valid, False otherwise.
        """
        verify_url = app.config.get("SSO_BROKER_VERIFY_NONCE_URL")
        if not verify_url:
            app.logger.error("SSO_BROKER_VERIFY_NONCE_URL not configured")
            return False

        bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")
        if not bearer_token:
            app.logger.error("COMMONS_PROFILES_API_TOKEN not set")
            return False

        timeout = app.config.get("SSO_BROKER_SILENT_LOGIN_TIMEOUT", 3)
        try:
            resp = requests.post(
                verify_url,
                json={"nonce": nonce},
                headers={
                    "Authorization": f"Bearer {bearer_token}",
                    "Content-Type": "application/json",
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.json().get("valid", False) is True
        except Exception:
            app.logger.exception("Nonce verification request failed")
            return False


class UserDataAPIClient:
    """Client for interacting with a remote user data source's API."""

    @staticmethod
    def fetch_user_profile(
        sub_id: str | None = None,
        kc_username: str | None = None,
        timeout: int | None = None,
    ) -> APIResponse | Profile | None:
        """Fetch user profile data from the API endpoint.

        Note that this function returns None if the API request failed or the response
        cannot be parsed. If the user was not found it will *still* return an APIResponse
        or Profile object:
            APIResponse - the `data` property will be an empty list
            Profile - there will be no `results` property and `meta.error.message` will
                read "User not found".

        Args:
            sub_id: The subject ID to query for (exclusive of kc_username)
            kc_username: The username to query for (exclusive of sub_id)
            timeout: The timeout duration for the API request in seconds (default 10).

        Raises:
            requests.Timeout: If the request to the profiles user data API fails to
                yield a timely response.
            requests.RequestException: If there were other kinds of errors communicating
                with the user data API (e.g., connection problems).

        Returns:
            APIResponse | Profile | None: Parsed response data or None if the API request
                fails or the response cannot be parsed.
        """
        if not timeout:
            timeout = app.config.get("REMOTE_USER_DATA_API_TIMEOUT", 5)

        if not sub_id and not kc_username:
            raise ValueError("sub_id or kc_username must be provided")

        if sub_id and kc_username:
            raise ValueError("sub_id and kc_username cannot both be provided")

        # Get bearer token from environment variable
        bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")

        if not bearer_token:
            raise ValueError(
                "COMMONS_PROFILES_API_TOKEN environment variable not found"
            )

        # Prepare headers
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }

        # Build the API endpoint URL
        base_api_url = app.config.get("IDMS_BASE_API_URL")

        if sub_id:
            url = f"{base_api_url}subs/?sub={sub_id}"
        else:
            url = f"{base_api_url}members/{kc_username}/"

        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()  # Raises an HTTPError for bad responses

            # Parse JSON response
            json_data = response.json()

            # Parse with Pydantic
            # if we have a sub_id we expect an APIResponse object that has a
            # sub and profile. If we have a kc_username we expect a Profile object.
            if sub_id:
                parsed_response = APIResponse(**json_data)
            else:
                parsed_response = Profile(**json_data.get("results", json_data))

            return parsed_response

        except requests.Timeout as e:
            message = f"API request for user data timed out after {timeout} seconds"
            app.logger.error(message)
            raise e
        except requests.RequestException as e:
            message = "API request for user data failed"
            app.logger.error(message)
            raise e
        except Exception as e:
            message = "Error parsing api response from user data endpoint"
            app.logger.error(message)
            app.logger.error(e)
            return None

    @staticmethod
    def send_logout_to_profiles(user_name: str, timeout: int | None = None) -> bool:
        """Notify Profiles API that a user has logged out.

        For a successful request, the API should return 200:

            {
                "message": "Action successfully triggered.",
                "data": {
                    "user": {
                        "user": "john_doe",
                        "url": "/profiles/john_doe/"
                    },
                    "user_agent": "Mozilla/5.0 ...",
                    "app": ["Profiles", "Works", "WordPress"]
                }
            }

        Error responses can include:

            HTTP 400 - Validation Error:

            {
                "error": "Validation failed",
                "details": {
                    "user_name": ["Username cannot be empty"],
                    "user_agent": ["User agent cannot be empty"]
                }
            }
            HTTP 401 - Unauthorized: Missing or invalid Bearer token.

            HTTP 500 - Server Error:

            {
                "error": "An unexpected error occurred"
            }

        Args:
            user_name: The username of the user logging out
            timeout: The timeout duration in seconds for the logout signal request. (Optional)

        Returns:
            True if successful, False otherwise
        """
        if not timeout:
            timeout = 15
        endpoint = f"{app.config.get('IDMS_BASE_API_URL')}actions/logout/"

        headers = {
            "Authorization": f"Bearer {os.getenv('COMMONS_PROFILES_API_TOKEN')}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        user_agent = request.headers.get("User-Agent")
        body = LogoutRequest(
            user_name=user_name,
            user_agent=user_agent,
        )

        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=body.model_dump(),
                timeout=timeout,
            )

            if 200 <= response.status_code < 300:
                try:
                    resp_json = response.json()
                    assert resp_json["data"]["user"]["user"] == user_name
                    assert resp_json["data"]["user_agent"] == user_agent
                    assert "successful" in resp_json["message"]
                    app.logger.debug(
                        f"DEBUG: received successful response: {resp_json}"
                    )
                    return True

                except (AssertionError, KeyError):
                    app.logger.error(
                        f"Profiles logout API returned unexpected response logging out user {user_name}: {response.text}",
                        exc_info=True,
                    )
                    return False

            else:
                app.logger.error(
                    f"Profiles logout API returned HTTP {response.status_code}: {response.text[:400]}"
                )
                return False

        except requests.RequestException as e:
            app.logger.error(
                f"Error sending logout to Profiles API: {e}", exc_info=True
            )
            return False
