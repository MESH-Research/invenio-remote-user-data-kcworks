"""This module provides functions and classes for interacting with the IDMS API."""

import os
import requests
from flask import current_app, request
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


class SubData(BaseModel):
    """SubData is a Pydantic model for the user profile."""

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

    Returns:
        APIResponse | Profile | None: Parsed response data or None if the API request
            fails or the response cannot be parsed.
    """
    if not timeout:
        timeout = current_app.config.get("REMOTE_USER_DATA_API_TIMEOUT", 5)

    if not sub_id and not kc_username:
        raise ValueError("sub_id or kc_username must be provided")

    if sub_id and kc_username:
        raise ValueError("sub_id and kc_username cannot both be provided")

    # Get bearer token from environment variable
    bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")

    if not bearer_token:
        raise ValueError("COMMONS_PROFILES_API_TOKEN environment variable not found")

    # Prepare headers
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
    }

    # Build the API endpoint URL
    base_api_url = current_app.config.get("IDMS_BASE_API_URL")

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
            parsed_response = Profile(**json_data)

        return parsed_response

    except requests.Timeout:
        message = f"API request for user data timed out after {timeout} seconds"
        current_app.logger.error(message)
        return None
    except requests.RequestException:
        message = "API request for user data failed"
        current_app.logger.error(message)
        return None
    except Exception:
        message = "Error parsing api response from user data endpoint"
        current_app.logger.error(message)
        return None


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
        timeout = current_app.config.get("IDMS_TOKEN_UPDATE_TIMEOUT", 5)

    # Get user agent from current request
    user_agent = request.headers.get("User-Agent", "Unknown")

    base_api_url = current_app.config.get("IDMS_BASE_API_URL")
    api_url = f"{base_api_url}tokens/"

    # Get bearer token from environment variable
    bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")

    if not bearer_token:
        raise ValueError("COMMONS_PROFILES_API_TOKEN environment variable not found")

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
    response = requests.post(api_url, json=payload, headers=headers, timeout=timeout)

    # Raise an exception if the request fails
    response.raise_for_status()

    return response
