#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Group roles service for Invenio accounts (roles as groups)."""

from collections.abc import Iterable
from pprint import pformat
from typing import Any, cast

from flask import current_app as app
from invenio_accounts.models import Role, User
from invenio_accounts.proxies import current_accounts

# TODO: Most of these operations use the invenio_accounts datastore
# directly. The invenio-users-resources groups service may be appropriate,
# but it seems not to support the same kind of record operations.


class GroupRolesService:
    """Service for group roles (Invenio roles used as groups)."""

    def __init__(self, service=None, *args, **kwargs):
        """Initialize the service.

        The ``service`` argument is accepted for API compatibility and is unused.
        """
        pass

    def get_roles_for_remote_group(self, remote_group_id: str, idp: str) -> list[Role]:
        """Get the Invenio roles for a remote group.

        Returns:
            The local roles mapped to the remote group.
        """
        query_string = f"{idp}---{remote_group_id}|"

        query = current_accounts.datastore.role_model.query.filter(
            Role.id.contains(query_string)
        )

        local_groups = query.all()

        return local_groups

    @staticmethod
    def get_current_members_of_group(group_name: str) -> list[User]:
        """Fetch the users assigned the given group role.

        Returns:
            The users currently assigned to the role.
        """
        my_group_role = current_accounts.datastore.find_role(group_name)
        return [user for user in my_group_role.users]

    def get_current_user_roles(self, user: str | User) -> list[Role]:
        """Get the current roles for a user.

        Returns:
            The current roles assigned to the user.

        Raises:
            RuntimeError: If the user cannot be found.
        """
        if isinstance(user, str):
            return_user = current_accounts.datastore.find_user(email=user)
        else:
            return_user = user
        if return_user is None:
            raise RuntimeError(f'User "{user}" not found.')
        return cast("list[Role]", list(cast(Iterable[Any], return_user.roles)))

    def find_or_create_group(self, group_name: str, **kwargs) -> Role | None:
        """Find or create a group with the given name.

        Returns:
            The existing or newly created role.

        Raises:
            RuntimeError: If the role cannot be found or created.
        """
        my_group_role = current_accounts.datastore.find_or_create_role(
            name=group_name, **kwargs
        )
        current_accounts.datastore.commit()
        if my_group_role is not None:
            app.logger.debug(f'Role for group "{group_name}" found or created.')
        else:
            raise RuntimeError(f'Role for group "{group_name}" not found or created.')
        return my_group_role

    def create_new_group(self, group_name: str, **kwargs) -> Role | None:
        """Create a new group with the given name.

        Returns:
            The newly created role.

        Raises:
            RuntimeError: If the role cannot be created.
        """
        my_group_role = current_accounts.datastore.create_role(
            name=group_name, **kwargs
        )
        current_accounts.datastore.commit()
        if my_group_role is not None:
            app.logger.info(f'Role "{group_name}" created successfully.')
        else:
            raise RuntimeError(f'Role "{group_name}" not created.')
        return my_group_role

    def delete_group(self, group_name: str, **kwargs) -> bool:
        """Delete a group role with the given name.

        Returns:
            True if the group was deleted successfully, otherwise ``False``.

        Raises:
            RuntimeError: If the role cannot be found or deleted.
        """
        deleted = False
        my_group_role = current_accounts.datastore.find_role(group_name)
        if my_group_role is None:
            raise RuntimeError(f'Role "{group_name}" not found.')
        else:
            try:
                current_accounts.datastore.delete(my_group_role)
                current_accounts.datastore.commit()
                app.logger.info(f'Role "{group_name}" deleted successfully.')
                deleted = True
            except AttributeError as a:
                app.logger.error(a)
                deleted = True
            except Exception as e:
                raise RuntimeError(
                    f'Role "{group_name}" not deleted. {pformat(e)}'
                ) from e
        return deleted

    def add_user_to_group(self, group_name: str, user: User, **kwargs) -> bool:
        """Add a user to a group.

        Returns:
            ``True`` when the user was added successfully.

        Raises:
            RuntimeError: If the user could not be added to the role.
        """
        app.logger.debug(f"got group name {group_name}")
        user_added = current_accounts.datastore.add_role_to_user(user, group_name)
        current_accounts.datastore.commit()
        if user_added is False:
            raise RuntimeError("Cannot add user to group role.")
        else:
            user_str = user.email if isinstance(user, User) else user
            app.logger.info(
                f'Role "{group_name}" added to user "{user_str}" successfully.'
            )
        return user_added

    def find_group(self, group_name: str) -> Role | None:
        """Find a group role with the given name.

        Returns:
            The matching role, if found.
        """
        my_group_role = current_accounts.datastore.find_role(group_name)
        if my_group_role is None:
            app.logger.debug(f'Role "{group_name}" not found.')
        else:
            app.logger.debug(f'Role "{group_name}" found successfully.')
        return my_group_role

    def remove_user_from_group(
        self, group_name: str | Role, user: str | User, **kwargs
    ) -> bool:
        """Remove a group role from a user.

        Args:
            group_name: The name of the group to remove the user from,
                or the Role object for the group.
            user: The user object to remove from the group, or the user's email.
            **kwargs: Accepted for API compatibility and ignored.

        Returns:
            ``True`` if the role was removed from the user.
        """
        user = (
            user
            if isinstance(user, User)
            else current_accounts.datastore.get_user_by_id(user)
        )
        group_name = group_name if isinstance(group_name, str) else group_name.id
        removed_user = current_accounts.datastore.remove_role_from_user(
            user, group_name
        )
        current_accounts.datastore.commit()
        if removed_user is False:
            app.logger.debug("Role {group_name} could not be removed from user.")
        else:
            app.logger.info(
                f'Role "{group_name}" removed from user "{user.email}"successfully.'
            )
        return removed_user
