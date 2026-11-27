# Copyright (C) 2023-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Jinja filter that dumps a user profile object to a dict for templates."""

import json

from flask import current_app

from invenio_remote_user_data_kcworks.services.user_profile import UserProfileService
from invenio_remote_user_data_kcworks.utils.names import get_given_name


def user_profile_dict(user_profile):
    """Convert a user profile object to a dictionary with all profile fields.

    Include all possible name variants in the dictionary.
    Returns `{}` for anonymous users or when the profile has no user_profile data.

    Args:
        user_profile: The user profile object to convert.

    Returns:
        dict: A dictionary containing all user profile fields.
    """
    profile_data = getattr(user_profile, "user_profile", None) if user_profile else None
    if not profile_data:
        return {}

    profile_fields = current_app.config.get(
        "ACCOUNTS_USER_PROFILE_SCHEMA", {}
    ).fields.keys()

    profile_id = getattr(user_profile, "id", None) if user_profile else None
    profile_dict = {"id": profile_id if profile_id else ""}

    for field in profile_fields:
        profile_dict[field] = profile_data.get(field, "")

    name_parts = profile_data.get("name_parts_local") or profile_data.get("name_parts")
    if name_parts:
        try:
            parts = (
                json.loads(name_parts) if isinstance(name_parts, str) else name_parts
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            parts = {}
        if isinstance(parts, dict):
            # Remote sync uses "first"; local name parts use "given".
            # Never fall back to full_name here — callers use email instead.
            given = get_given_name(parts).strip()
            if given:
                profile_dict["first_name"] = given

    profile_dict.update(
        UserProfileService.get_user_name_variants(profile_id, profile_data)
    )
    return profile_dict
