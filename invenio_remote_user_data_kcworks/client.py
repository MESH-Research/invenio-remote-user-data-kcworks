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
from pydantic import BaseModel, HttpUrl


class AcademicInterest(BaseModel):
    """AcademicInterest is a Pydantic model of data associated with a user."""

    id: int
    text: str


class Group(BaseModel):
    """Group model representing a user's group membership."""

    id: int
    group_name: str | None = None
    role: str
    url: HttpUrl | None = None


class Profile(BaseModel):
    """Profile is a Pydantic model of a user."""

    username: str
    name: str
    email: str
    first_name: str
    last_name: str
    institutional_affiliation: str
    orcid: str
    academic_interests: list[AcademicInterest] | None = None
    groups: list[Group]
    url: HttpUrl | None = None
    is_superadmin: bool = False


class SubData(BaseModel):
    """SubData is a Pydantic model for the user data for a sub."""

    sub: str
    profile: Profile


class Meta(BaseModel):
    """Meta is a Pydantic model that represents the metadata of the response."""

    authorized: bool


class APIResponse(BaseModel):
    """APIResponse is a Pydantic model that represents the API endpoint."""

    data: list[SubData]
    meta: Meta
    next: str | None
    previous: str | None


class LogoutRequest(BaseModel):
    """A Pydantic model representing the signal to be sent for global logout."""

    user_name: str
    user_agent: str


class UserDataAPIClient:
    """Client for interacting with a remote user data source's API."""

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

            # Parse JSON response
            json_data = response.json()

            # Parse with Pydantic
            # if we have a sub_id we expect an APIResponse object that has a
            # sub and profile. If we have a kc_username we expect a Profile object.
            if sub_id or use_sub_endpoint:
                parsed_response = APIResponse(**json_data)
            else:
                parsed_response = Profile(**json_data)

            return parsed_response

        except requests.Timeout as e:
            message = f"API request for user data timed out after {timeout} seconds"
            app.logger.error(message)
            raise e
        except requests.RequestException as e:
            message = "API request for user data failed"
            app.logger.error(message)
            raise e
        except Exception:
            message = "Error parsing api response from user data endpoint"
            app.logger.error(message)
            return None

    @staticmethod
    def update_token_information(
        access_token: str,
        refresh_token: str,
        user_name: str,
        app: str = "Works",
        timeout: int | None = None,
    ) -> requests.Response:
        """Make a POST API request with token data for storage and revocation.

        Args:
            access_token: User's access token
            refresh_token: User's refresh token
            user_name: Username to send
            app: Application name (defaults to "Profiles")
            timeout: Request timeout in seconds

        Returns:
            requests.Response object

        Raises:
            requests.RequestException: If the request fails
        """
        if not timeout:
            timeout = app.config.get("IDMS_TOKEN_UPDATE_TIMEOUT", 5)

        # Get user agent from current request
        user_agent = request.headers.get("User-Agent", "Unknown")

        base_api_url = app.config.get("IDMS_BASE_API_URL")
        api_url = f"{base_api_url}tokens/"

        # Get bearer token from environment variable
        bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")

        if not bearer_token:
            raise ValueError(
                "COMMONS_PROFILES_API_TOKEN environment variable not found"
            )

        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }

        # Prepare the payload
        payload = {
            "user_agent": user_agent,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "app": app,
            "user_name": user_name,
        }

        # Make the POST request
        response = requests.post(
            api_url, json=payload, headers=headers, timeout=timeout
        )

        # Raise an exception if the request fails
        response.raise_for_status()

        return response

    @staticmethod
    def send_logout_to_profiles(user_name: str, timeout: int | None = None) -> bool:
        """
        Notify Profiles API that a user has logged out.

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

                except (AssertionError, KeyError) as e:
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
