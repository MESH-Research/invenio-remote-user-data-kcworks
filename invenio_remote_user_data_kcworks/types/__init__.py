# Part of package Invenio-Remote-User-Data-KCWorks
# Copyright (C) 2023-2026, MESH Research
#
# package Invenio-Remote-User-Data-KCWorks is free software; you can redistribute and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Public type and model exports for invenio-remote-user-data-kcworks."""

from .auth import AccountInfo
from .broker_payload import BrokerDecodedToken, BrokerDecodedUserinfo
from .names import (
    NameAffiliationDict,
    NameIdentifierDict,
    NamePropsDict,
    NamesRecordDict,
)
from .orcid import (
    OrcidActivitiesSummary,
    OrcidAffiliationGroupEntry,
    OrcidDisambiguatedOrg,
    OrcidEmployments,
    OrcidEmploymentSummary,
    OrcidExpandedResult,
    OrcidExpandedSearchResponse,
    OrcidIdentifierBlock,
    OrcidName,
    OrcidOrganization,
    OrcidPerson,
    OrcidRecord,
)
from .profiles_api import (
    APIResponse,
    AcademicInterest,
    Group,
    LogoutRequest,
    Meta,
    Profile,
    SubData,
)
from .users import (
    CalculatedUserDataDict,
    GroupChangesDict,
    UpdateLocalUserDataResultDict,
    UserChangesDict,
    UserProfileUpdateDict,
)

__all__ = (
    "APIResponse",
    "AcademicInterest",
    "AccountInfo",
    "BrokerDecodedToken",
    "BrokerDecodedUserinfo",
    "CalculatedUserDataDict",
    "Group",
    "GroupChangesDict",
    "LogoutRequest",
    "Meta",
    "NameAffiliationDict",
    "NameIdentifierDict",
    "NamePropsDict",
    "NamesRecordDict",
    "OrcidActivitiesSummary",
    "OrcidAffiliationGroupEntry",
    "OrcidDisambiguatedOrg",
    "OrcidEmployments",
    "OrcidEmploymentSummary",
    "OrcidExpandedResult",
    "OrcidExpandedSearchResponse",
    "OrcidIdentifierBlock",
    "OrcidName",
    "OrcidOrganization",
    "OrcidPerson",
    "OrcidRecord",
    "Profile",
    "SubData",
    "UpdateLocalUserDataResultDict",
    "UserChangesDict",
    "UserProfileUpdateDict",
)
