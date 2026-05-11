# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Functions and classes for interacting with the IDMS API."""

import os
import time
from typing import Literal, overload

import requests
from flask import current_app as app
from flask import request

from .config import UserDataEvent, UserDataStatus
from .types.profiles_api import APIResponse, LogoutRequest, Profile


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
            `broker_token`), or None if there is no session or the request
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

    @overload
    @staticmethod
    def fetch_user_profile(
        *,  # make it clear that following must be passed as keyword args
        sub_id: str,
        kc_username: None = None,
        timeout: int | None = None,
        use_sub_endpoint: bool | None = None,
    ) -> APIResponse | None: ...

    @overload
    @staticmethod
    def fetch_user_profile(
        *,
        sub_id: None = None,
        kc_username: str,
        timeout: int | None = None,
        use_sub_endpoint: Literal[True],
    ) -> APIResponse | None: ...

    @overload
    @staticmethod
    def fetch_user_profile(
        *,
        sub_id: None = None,
        kc_username: str,
        timeout: int | None = None,
        use_sub_endpoint: Literal[False] | None = None,
    ) -> Profile | None: ...

    @staticmethod
    def fetch_user_profile(
        sub_id: str | None = None,
        kc_username: str | None = None,
        timeout: int | None = None,
        use_sub_endpoint: bool | None = None,
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
            use_sub_endpoint: A flag to indicate that a request using the kc_username should
              be made to the sub endpoint rather than the members endpoint. This does nothing
              if a sub_id is supplied. If a kc_username is supplied it overrides the default
              behaviour that uses the members endpoint.

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
        elif use_sub_endpoint:
            url = f"{base_api_url}subs/{kc_username}/"
        else:
            url = f"{base_api_url}members/{kc_username}/"
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()  # Raises an HTTPError for bad responses

            json_data = response.json()

            if sub_id or use_sub_endpoint:
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

        user_agent = request.headers.get("User-Agent") or ""
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
                        "Profiles logout API returned unexpected "
                        "response logging out user %r: %s",
                        user_name,
                        response.text[:400],
                    )
                    return False

            else:
                app.logger.error(
                    f"Profiles logout API returned HTTP {response.status_code}: "
                    f"{response.text[:400]}"
                )
                return False

        except requests.RequestException as e:
            app.logger.error(
                f"Error sending logout to Profiles API: {e}", exc_info=True
            )
            return False

    @staticmethod
    def send_user_status_callback(
        *,
        sub: str,
        username: str | None,
        status: UserDataStatus,
        event: UserDataEvent,
        retry_at: str | None = None,
        note: str | None = None,
        max_attempts: int = 3,
        timeout: int | None = None,
    ) -> bool:
        """Notify the Profiles API that a user create/update job finished.

        POSTs to
        `{IDMS_BASE_API_URL}members/{username or "unknown"}/works/status`
        with a Bearer-token-protected JSON body of the form::

            {
                "username": "<kc_username>" | null,
                "sub":      "<oauth sub>",
                "status":   "PROCESSED" | "FAILED",
                "event":    "created"   | "updated",
                "retry_at": "<ISO 8601 UTC timestamp>",   // optional
                "note":     "<freeform diagnostic>"       // optional
            }

        The webhook's `id` field is the OAuth `sub` (i.e. the
        value stored as `UserIdentity.id`), not the KC member name,
        so callers must resolve the member name locally
        (sub -> `UserIdentity` -> `User.user_profile`) before
        invoking this method. When the resolution fails (e.g. an
        early failure in `do_user_created` before the local user
        has been created) callers may pass `username=None` and the
        callback will still fire under the `unknown` URL slot, with
        the raw `sub` in the body so the Profiles operator can
        correlate.

        The `event` value mirrors the `event` property carried by
        each entry in the inbound `updates.users` webhook payload, so
        the Profiles side can correlate the status callback with the
        original signal it sent.

        `retry_at` should be set when `status == UserDataStatus.FAILED`
        and the Works task has scheduled (or auto-rescheduled) another
        attempt for that timestamp, so the Profiles side can avoid
        prompting an operator for manual remediation while a retry is
        still pending.

        The call is best-effort with bounded inline retries (1 s, 2 s,
        4 s, ... exponential backoff between failures); we never let a
        Profiles outage block the underlying user-update task itself.

        Args:
            sub: The OAuth `sub` from the webhook
                (`UserIdentity.id`). Required; empty values
                short-circuit to `False` with a warning.
            username: The KC member name resolved from the sub, or
                `None` when no local user is known yet. Used to
                construct the URL (falling back to `"unknown"`) and
                included verbatim in the body.
            status: `UserDataStatus` member.
                `UserDataStatus.PROCESSED` or `UserDataStatus.FAILED`.
            event: `UserDataEvent` member, mirroring the inbound
                webhook `event` field.
            retry_at: Optional ISO 8601 UTC timestamp of the next
                scheduled attempt.
            note: Optional freeform diagnostic string (e.g. exception
                class name or a short reason).
            max_attempts: Total number of POST attempts before giving
                up and logging an error.
            timeout: Per-request timeout in seconds (default 5).

        Returns:
            `True` when the callback was accepted (HTTP 2xx) on any
            attempt, `False` otherwise.
        """
        if not sub:
            app.logger.warning(
                "send_user_status_callback: empty sub; skipping (status=%s event=%s)",
                status,
                event,
            )
            return False
        if not isinstance(status, UserDataStatus):
            app.logger.error(
                "send_user_status_callback: invalid status %r "
                "(expected UserDataStatus member)",
                status,
            )
            return False
        if not isinstance(event, UserDataEvent):
            app.logger.error(
                "send_user_status_callback: invalid event %r "
                "(expected UserDataEvent member)",
                event,
            )
            return False

        base_api_url = app.config.get("IDMS_BASE_API_URL")
        bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")
        if not base_api_url or not bearer_token:
            app.logger.warning(
                "send_user_status_callback: IDMS_BASE_API_URL or "
                "COMMONS_PROFILES_API_TOKEN missing; skipping "
                "(sub=%s username=%s status=%s)",
                sub,
                username,
                status,
            )
            return False

        member_slug = (username or "").strip() or "unknown"
        url = f"{base_api_url}members/{member_slug}/works/status"
        # `StrEnum` members serialise as their bare string value via
        # `json.dumps`, so the wire format is unchanged.
        body: dict[str, str | None] = {
            "username": (username or None),
            "sub": sub,
            "status": status,
            "event": event,
        }
        if retry_at:
            body["retry_at"] = retry_at
        if note:
            body["note"] = note

        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        timeout = timeout or 5
        error_args = [
            max_attempts,
            sub,
            username,
            status,
        ]

        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                resp = requests.post(url, headers=headers, json=body, timeout=timeout)
                if 200 <= resp.status_code < 300:
                    app.logger.debug(
                        "send_user_status_callback: ok sub=%s username=%s "
                        "status=%s event=%s attempt=%s",
                        sub,
                        username,
                        status,
                        event,
                        attempt,
                    )
                    return True
                app.logger.warning(
                    "send_user_status_callback: HTTP %s on attempt %s/%s "
                    "for sub=%s username=%s status=%s body=%s",
                    resp.status_code,
                    attempt,
                    *error_args,
                    resp.text[:200],
                )
            except (requests.RequestException, requests.Timeout) as exc:
                last_exc = exc
                app.logger.warning(
                    "send_user_status_callback: %r on attempt %s/%s for "
                    "sub=%s username=%s status=%s",
                    exc,
                    attempt,
                    *error_args,
                )
            if attempt < max_attempts:
                time.sleep(2 ** (attempt - 1))

        app.logger.error(
            "send_user_status_callback: gave up after %s attempts for "
            "sub=%s username=%s status=%s event=%s last_error=%r",
            *error_args,
            event,
            last_exc,
        )
        return False
