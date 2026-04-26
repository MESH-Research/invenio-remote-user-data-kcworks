# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Proxy objects for the extension's current instance and its services."""

from flask import current_app
from werkzeug.local import LocalProxy

current_remote_user_data = LocalProxy(
    lambda: current_app.extensions["invenio-remote-user-data-kcworks"]
)

current_remote_user_data_service = LocalProxy(lambda: current_remote_user_data.service)

current_remote_group_service = LocalProxy(
    lambda: current_remote_user_data.group_service
)

current_names_sync_service = LocalProxy(
    lambda: current_remote_user_data.names_sync_service
)
