"""Tests for the group-role helper service."""

# from invenio_utilities_tuw.utils import get_user_by_identifier
# from pprint import pprint
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService


def test_get_current_user_roles(app, user_factory):
    """Test fetching a user's current roles."""
    myuser = user_factory()
    roles = GroupRolesService(current_remote_user_data_service).get_current_user_roles(
        user=myuser
    )
    assert roles == []


def test_find_or_create_group(app, user_factory, db):
    """Test fetching or creating a group role."""
    grouper = GroupRolesService(current_remote_user_data_service)
    my_group_role = grouper.find_or_create_group(
        group_name="my_group", description="A group for me"
    )
    assert my_group_role.name == "my_group"
    assert my_group_role.description == "A group for me"

    myuser = user_factory()
    grouper.add_user_to_group(group_name="my_group", user=myuser)
    assert [u for u in my_group_role.users] == [myuser]
    assert [u for u in my_group_role.actionusers] == []


def test_create_new_group(app, user_factory, db):
    """Test creating a new group role."""
    grouper = GroupRolesService(current_remote_user_data_service)
    my_group_role = grouper.create_new_group(
        group_name="my_group", description="A group for me"
    )
    assert my_group_role.name == "my_group"
    assert my_group_role.description == "A group for me"
    assert [u for u in my_group_role.users] == []
    assert [u for u in my_group_role.actionusers] == []


def test_add_user_to_group(app, user_factory, db):
    """Test adding a user to a group role."""
    grouper = GroupRolesService(current_remote_user_data_service)
    my_group_role = grouper.create_new_group(
        group_name="my_group", description="A group for me"
    )
    assert my_group_role
    myuser = user_factory()
    user_added = grouper.add_user_to_group("my_group", myuser)
    assert user_added is True

    from werkzeug.local import LocalProxy

    security_datastore = LocalProxy(lambda: app.extensions["security"].datastore)
    my_user = security_datastore.find_user(email=myuser.email)
    # my_user = get_user_by_identifier(users[0].email)
    assert "my_group" in my_user.roles


def test_get_current_members_of_group(app, user_factory, db):
    """Test listing the current members of a group."""
    grouper = GroupRolesService(current_remote_user_data_service)
    my_group_role = grouper.find_or_create_group(
        group_name="my_group", description="A group for me"
    )
    assert my_group_role
    myuser = user_factory()
    added_user = grouper.add_user_to_group(group_name="my_group", user=myuser)
    assert added_user is True
    members_of_group = grouper.get_current_members_of_group(group_name="my_group")

    assert [u for u in members_of_group] == [myuser]
