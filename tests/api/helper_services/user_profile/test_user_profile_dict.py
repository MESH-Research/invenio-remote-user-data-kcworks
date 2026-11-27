# Copyright (C) 2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Tests for Jinja `user_profile_dict` display_name exposure."""

import json

from invenio_db import db

from invenio_remote_user_data_kcworks.filters.user_profile_dict import (
    user_profile_dict,
)


def _set_profile(user, **fields):
    profile = dict(user.user_profile or {})
    profile.update(fields)
    user.user_profile = profile
    db.session.commit()
    return user


def test_user_profile_dict_includes_display_name(user_factory, app):
    """Jinja `user_profile_dict` exposes `display_name` from the schema."""
    u = user_factory(email="profiledict@example.org", kc_username="profiledict")
    _set_profile(
        u.user,
        full_name="Ada Lovelace",
        display_name="Lovelace, Ada",
        name_parts=json.dumps({"first": "Ada", "last": "Lovelace"}),
    )

    with app.test_request_context():
        result = user_profile_dict(u.user)

    assert result["display_name"] == "Lovelace, Ada"
    assert result["full_name"] == "Ada Lovelace"
