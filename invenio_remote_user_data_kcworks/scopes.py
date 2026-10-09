# Part of Invenio-Remote-User-Data-KCWorks
# Copyright (C) 2023-2026, MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute
# and/or modify it under the terms of the MIT License; see LICENSE file
# for more details.

"""OAuth scopes for inbound user/group sync and SSO logout webhooks.

Registered via `invenio_oauth2server.scopes` entry points. Both are
internal so they do not appear in the personal-token creation UI.
"""

from invenio_i18n import lazy_gettext as _
from invenio_oauth2server.models import Scope

webhooks_user_data_scope = Scope(
    id_="webhooks:user-data",
    group="webhooks",
    help_text=_("Trigger user and group metadata sync from Commons Profiles."),
    internal=True,
)

webhooks_logout_scope = Scope(
    id_="webhooks:logout",
    group="webhooks",
    help_text=_("Trigger single-sign-out session invalidation."),
    internal=True,
)
