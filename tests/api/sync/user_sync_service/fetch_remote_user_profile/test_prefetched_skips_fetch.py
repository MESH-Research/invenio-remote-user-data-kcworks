# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Skip Profiles when a usable remote profile is already in hand.

Covers:

- If we already have an authorized profile in hand, we do not call Profiles
  again.

Related coverage elsewhere:

- Missing local user → `test_local_user_missing.py`.
- Unusable remote responses → `test_unusable_profile_stops.py`.
- How we look up Profiles (URLs, fallback, IdP key) → `test_lookup_path.py`.
"""

from unittest.mock import patch

from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from tests.fixtures.idms import minimal_api_response, minimal_profile


def test_update_user_from_remote_prefetched_skips_fetch(app, user_factory, db):
    """Authorized profile in hand: do not call Profiles again."""
    myuser = user_factory(
        email="prefetch@example.org",
        oauth_src=None,
        oauth_id=None,
        kc_username=None,
    )
    UserIdentity.create(myuser.user, "knowledgeCommons", "sub-prefetch")
    remote_in = minimal_api_response(
        "sub-prefetch",
        profile=minimal_profile(
            username="pref",
            email="prefetch@example.org",
        ),
    )

    with patch(
        "invenio_remote_user_data_kcworks.services.service.UserDataAPIClient."
        "fetch_user_profile",
    ) as fetch_mock:
        out = user_data_service.update_user_from_remote(
            system_identity,
            myuser.id,
            "knowledgeCommons",
            "sub-prefetch",
            remote_data=remote_in,
        )

    fetch_mock.assert_not_called()
    assert out[0].id == myuser.user.id
    assert out[0].username == "pref"
    assert out[0].user_profile.get("identifier_kc_username") == "pref"
