"""Custom permission policy to allow direct adding of users to communities."""

from invenio_access import action_factory, Permission
from invenio_administration.generators import Administration

# from invenio_administration.permissions import administration_access_action
from invenio_communities.permissions import CommunityPermissionPolicy
from invenio_communities.generators import (
    AllowedMemberTypes,
    CommunityManagersForRole,
    GroupsEnabled,
)
from invenio_records_permissions import BasePermissionPolicy
from invenio_records_permissions.generators import (
    AnyUser,
    SystemProcess,
)


class CustomCommunitiesPermissionPolicy(CommunityPermissionPolicy):
    """Communities permission policy of Datasafe."""

    can_members_add = [
        CommunityManagersForRole(),
        AllowedMemberTypes("user", "group"),
        GroupsEnabled("group"),
        SystemProcess(),
    ]


# trigger_update_action = action_factory("trigger-update")

# can_trigger_update = Permission(trigger_update_action)


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
