# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Service configurations for invenio-remote-user-data-kcworks service classes."""

from invenio_records_resources.services.base.config import (
    ConfiguratorMixin,
    FromConfig,
    ServiceConfig,
)


class RemoteUserDataServiceConfig(ServiceConfig, ConfiguratorMixin):
    """Service config class for the RemoteUserDataService."""

    permission_policy_cls = FromConfig(
        "REMOTE_USER_DATA_PERMISSION_POLICY", import_string=True
    )
    components = []
    service_id = "remote-user-data-service"
    endpoints_config = FromConfig("REMOTE_USER_DATA_API_ENDPOINTS")
    update_interval = FromConfig("REMOTE_USER_DATA_UPDATE_INTERVAL")
    api_timeout = FromConfig("REMOTE_USER_DATA_API_TIMEOUT", 5)
    kc_remote_idps = FromConfig("KC_REMOTE_IDPS")


class RemoteGroupDataServiceConfig(ServiceConfig, ConfiguratorMixin):
    """Service config class for the RemoteGroupDataService."""

    permission_policy_cls = FromConfig(
        "REMOTE_USER_DATA_PERMISSION_POLICY", import_string=True
    )
    components = []
    service_id = "remote-group-data-service"
    endpoints_config = FromConfig("REMOTE_USER_DATA_API_ENDPOINTS")
    update_interval = FromConfig("REMOTE_USER_DATA_UPDATE_INTERVAL")
    api_timeout = FromConfig("REMOTE_USER_DATA_API_TIMEOUT", 5)
    kc_remote_idps = FromConfig("KC_REMOTE_IDPS")
