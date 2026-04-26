# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""RDM record service components owned by ``invenio-remote-user-data-kcworks``.

These components plug into the host application's
``RDM_RECORDS_SERVICE_COMPONENTS`` and let this extension react to record
lifecycle events using its own services (notably ``NamesSyncService``).
"""

from .cited_names_component import CitedNamesUpsertComponent

__all__ = ("CitedNamesUpsertComponent",)
