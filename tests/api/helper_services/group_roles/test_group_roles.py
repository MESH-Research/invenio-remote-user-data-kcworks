# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""`GroupRolesService`: local Invenio roles used as groups.

Helper service under `api/helper_services/` — used by user-sync role reconcile
and group-sync apply. Not a remote Profiles surface and not
`update_group_from_remote` itself.

Covers:

- Create a role, add a user, list members, list a user’s roles.

Related coverage elsewhere:

- Remote groups ↔ local roles on a user →
  `sync/user_sync_service/apply_user_data_changes/test_reconcile_group_roles.py`.
- Applying a remote group onto roles/communities →
  `sync/group_sync_service/apply_group_data_changes/`.
"""

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService


def test_get_current_user_roles(app, user_factory):
    """Fetching a user's current roles returns an empty list when none."""
    myuser = user_factory().user
    roles = GroupRolesService(current_remote_user_data_service).get_current_user_roles(
        user=myuser
    )
    assert roles == []


def test_find_or_create_group(app, user_factory, db):
    """Finding or creating a group role, then adding a user."""
    grouper = GroupRolesService(current_remote_user_data_service)
    my_group_role = grouper.find_or_create_group(
        group_name="my_group", description="A group for me"
    )
    assert my_group_role.name == "my_group"
    assert my_group_role.description == "A group for me"

    myuser = user_factory().user
    grouper.add_user_to_group(group_name="my_group", user=myuser)
    assert [u for u in my_group_role.users] == [myuser]
    assert [u for u in my_group_role.actionusers] == []


def test_create_new_group(app, user_factory, db):
    """Creating a new group role with no members."""
    grouper = GroupRolesService(current_remote_user_data_service)
    my_group_role = grouper.create_new_group(
        group_name="my_group", description="A group for me"
    )
    assert my_group_role.name == "my_group"
    assert my_group_role.description == "A group for me"
    assert [u for u in my_group_role.users] == []
    assert [u for u in my_group_role.actionusers] == []


def test_add_user_to_group(app, user_factory, db):
    """Adding a user to a group role updates the user’s roles."""
    grouper = GroupRolesService(current_remote_user_data_service)
    my_group_role = grouper.create_new_group(
        group_name="my_group", description="A group for me"
    )
    assert my_group_role
    myuser = user_factory().user
    user_added = grouper.add_user_to_group("my_group", myuser)
    assert user_added is True

    from werkzeug.local import LocalProxy

    security_datastore = LocalProxy(lambda: app.extensions["security"].datastore)
    my_user = security_datastore.find_user(email=myuser.email)
    assert "my_group" in [role.name for role in my_user.roles]


def test_get_current_members_of_group(app, user_factory, db):
    """Listing current members of a group after adding a user."""
    grouper = GroupRolesService(current_remote_user_data_service)
    my_group_role = grouper.find_or_create_group(
        group_name="my_group", description="A group for me"
    )
    assert my_group_role
    myuser = user_factory().user
    added_user = grouper.add_user_to_group(group_name="my_group", user=myuser)
    assert added_user is True
    members_of_group = grouper.get_current_members_of_group(group_name="my_group")

    assert [u for u in members_of_group] == [myuser]
