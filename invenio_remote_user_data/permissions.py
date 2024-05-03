"""Custom permission policy to allow direct adding of users to communities."""

from invenio_communities.permissions import CommunityPermissionPolicy
from invenio_communities.generators import (
    AllowedMemberTypes,
    CommunityManagersForRole,
    GroupsEnabled,
)
from invenio_records_permissions.generators import (
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
