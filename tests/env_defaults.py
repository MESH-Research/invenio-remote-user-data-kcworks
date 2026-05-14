# Part of invenio-remote-user-data-kcworks.
# Copyright (C) 2024-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Central defaults for test process environment."""

from __future__ import annotations

import os

PYTEST_DEFAULT_COMMONS_PROFILES_API_TOKEN = "pytest-mock-commons-profiles-token"


def commons_profiles_api_token_is_live_configured() -> bool:
    """True when a non-placeholder Profiles bearer token is set.

    The session autouse fixture calls `setdefault` with
    `PYTEST_DEFAULT_COMMONS_PROFILES_API_TOKEN` so mocked client code always
    sees a value; live IDMS tests must skip unless the operator replaced it
    with a real token.

    Returns:
        Whether `COMMONS_PROFILES_API_TOKEN` is set to a live value.
    """
    t = os.environ.get("COMMONS_PROFILES_API_TOKEN")
    return bool(t and t != PYTEST_DEFAULT_COMMONS_PROFILES_API_TOKEN)
