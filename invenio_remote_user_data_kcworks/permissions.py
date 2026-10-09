# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Permission policies and access actions for remote user-data sync."""

from invenio_access import action_factory
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
    AdminAction,
    SystemProcess,
)
from invenio_users_resources.services.generators import (
    GroupsEnabled,
)

# Access actions for inter-app service accounts. Each is bound to a matching
# accounts_role of the same name via ActionRoles (see kcworks capabilities CLI).
users_sync_action = action_factory("users-sync")
groups_sync_action = action_factory("groups-sync")
users_logout_action = action_factory("users-logout")


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
    """Permission policy for Profiles sync and SSO logout webhooks.

    Service accounts receive narrow capability actions. `Administration` and
    `SystemProcess` remain as operator / internal overrides. Admin must not
    be assigned to those service accounts.
    """

    can_trigger_users_sync = [
        AdminAction(users_sync_action),
        Administration(),
        SystemProcess(),
    ]
    can_trigger_groups_sync = [
        AdminAction(groups_sync_action),
        Administration(),
        SystemProcess(),
    ]
    can_trigger_logout_user = [
        AdminAction(users_logout_action),
        Administration(),
        SystemProcess(),
    ]

    # Destructive / rare ops stay administration-only until a dedicated
    # consumer exists.
    can_delete_user_data = [
        Administration(),
        SystemProcess(),
    ]
    can_disown_collection = [
        Administration(),
        SystemProcess(),
    ]
