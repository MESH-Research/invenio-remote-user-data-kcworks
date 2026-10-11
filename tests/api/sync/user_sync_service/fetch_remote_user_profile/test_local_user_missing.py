# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Local account must exist before a Profiles fetch can run.

Covers:

- A missing local user is handled as not found (no Profiles fetch that
  depends on a real account).

Related coverage elsewhere:

- Skip fetch when a usable profile is already in hand →
  `test_prefetched_skips_fetch.py`.
- Unusable remote responses → `test_unusable_profile_stops.py`.
- How we look up Profiles (URLs, fallback, IdP key) → `test_lookup_path.py`.
"""

import pytest
from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_accounts

from invenio_remote_user_data_kcworks.errors import LocalUserNotFoundError
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)


def test_update_user_from_remote_local_user_missing(app):
    """A missing local user is handled as not found."""
    missing_id = 9_999_991
    assert current_accounts.datastore.get_user_by_id(missing_id) is None
    with pytest.raises(LocalUserNotFoundError, match="No local Invenio user"):
        user_data_service.update_user_from_remote(
            system_identity,
            missing_id,
            "knowledgeCommons",
            "sub-x",
        )
