#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Message queues related to user data operations."""

from flask import current_app


def declare_queues():
    """Declare the queues used by the extension.

    Returns:
        The queue configuration list consumed by Invenio.
    """
    return [
        {
            "name": "user-data-updates",
            "exchange": current_app.config["REMOTE_USER_DATA_MQ_EXCHANGE"],
        }
    ]
