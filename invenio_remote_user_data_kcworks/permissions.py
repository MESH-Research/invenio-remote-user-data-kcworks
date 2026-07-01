# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Custom permission policy to allow direct adding of users to communities."""

from invenio_administration.generators import Administration
from invenio_communities.generators import (
    AllowedMemberTypes,
    CommunityCurators,
    CommunityManagersForRole,
    CommunityMembers,
    CommunityOwners,
    ReviewPolicy,
)
from invenio_communities.permissions import (
    CommunityPermissionPolicy,
)
from invenio_records_permissions import BasePermissionPolicy
from invenio_records_permissions.generators import (
    # AnyUser,
    # Disable,
    SystemProcess,
)
from invenio_users_resources.services.generators import (
    GroupsEnabled,
)


class CustomCommunitiesPermissionPolicy(CommunityPermissionPolicy):
    """Communities permission policy of Datasafe."""

    can_set_theme = [CommunityOwners(), SystemProcess()]
    can_delete_theme = can_set_theme

    can_members_add = [
        CommunityManagersForRole(),
        AllowedMemberTypes("user", "group"),
        GroupsEnabled("group"),
        SystemProcess(),
    ]

    # who can include a record directly, without a review
    can_include_directly = [
        ReviewPolicy(
            closed_=[CommunityOwners()],  # default policy has Disable(),
            open_=[CommunityCurators()],
            members_=[CommunityMembers()],
        ),
        SystemProcess(),
    ]


class RemoteUserDataPermissionPolicy(BasePermissionPolicy):
    """Communities permission policy of Datasafe."""

    can_update = [
        Administration(),
        SystemProcess(),
    ]

    can_trigger_update = [
        Administration(),
        SystemProcess(),
    ]

    can_delete_user_data = [
        Administration(),
        SystemProcess(),
    ]

    can_disown_collection = [
        Administration(),
        SystemProcess(),
    ]

    can_logout_user = [
        Administration(),
        SystemProcess(),
    ]

    can_trigger_logout_user = [
        Administration(),
        SystemProcess(),
    ]
