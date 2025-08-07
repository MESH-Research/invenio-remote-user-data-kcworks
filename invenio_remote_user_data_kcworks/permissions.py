"""Custom permission policy to allow direct adding of users to communities."""

from invenio_access import Permission, action_factory
from invenio_administration.generators import Administration
from invenio_communities.generators import (
    AllowedMemberTypes,
    CommunityCurators,
    CommunityManagersForRole,
    CommunityOwners,
    IfPolicyClosed,
)

# from invenio_administration.permissions import administration_access_action
from invenio_communities.permissions import (
    CommunityPermissionPolicy,
)

# FIXME: This is a temporary hack since the GroupsEnabled generator
# has moved
try:
    from invenio_users_resources.services.generators import (
        GroupsEnabled,
    )
except ImportError:
    from invenio_communities.generators import GroupsEnabled

from invenio_records_permissions import BasePermissionPolicy
from invenio_records_permissions.generators import (
    AnyUser,
    Disable,
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

    # who can include a record directly, without a review
    can_include_directly = [
        IfPolicyClosed(
            "review_policy",
            then_=[
                SystemProcess(),
                CommunityOwners(),
            ],  # default policy has Disable(),
            else_=[CommunityCurators(), SystemProcess()],
        ),
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
