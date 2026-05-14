# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Tests of the group data sync service."""

from invenio_access.permissions import system_identity
from invenio_communities.proxies import current_communities
from invenio_rdm_records.proxies import (
    current_community_records_service,
    current_rdm_records_service,
)

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_group_service as group_data_service,
)


def test_update_group_from_remote_changes_visibility_with_public_record(
    running_app,
    db,
    search_clear,
    requests_mock,
    minimal_community_factory,
    minimal_published_record_factory,
    mock_send_remote_api_update_fixture,
):
    """Remote group update can change community visibility to restricted.

    The stock InvenioRDM policy forbids this when the community has a public
    record. This test checks the group data update while also checking that
    our override of that policy works. The final community visibility should
    be different from the record's access status.

    """
    app = running_app.app
    idp = "knowledgeCommons"
    remote_group_id = "1004290"

    community = minimal_community_factory(
        slug="the-inklings",
        metadata={
            "title": "The Inklings",
            "description": "A collection for testing.",
            "curation_policy": "",
            "page": "Page text.",
            "website": "https://hcommons-dev.org/groups/the-inklings/",
            "organizations": [
                {"name": "The Inklings"},
                {"name": "Knowledge Commons"},
            ],
        },
        access={
            "visibility": "public",
            "member_policy": "closed",
            "record_policy": "closed",
        },
        custom_fields={
            "kcr:commons_instance": idp,
            "kcr:commons_group_id": remote_group_id,
            "kcr:commons_group_name": "The Inklings",
            "kcr:commons_group_description": "",
            "kcr:commons_group_visibility": "public",
        },
        mock_search_api=False,
    )

    record = minimal_published_record_factory(
        community_list=[community.id],
    )
    record_ref = record._record

    return_payload = {
        "id": remote_group_id,
        "name": "The Inklings",
        "url": "https://hcommons-dev.org/groups/the-inklings/",
        "visibility": "hidden",
        "description": "Updated description.",
        "avatar": "",
        "groupblog": "",
        "upload_roles": ["member", "moderator", "administrator"],
        "moderate_roles": ["moderator", "administrator"],
    }
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]
    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    assert community["access"]["visibility"] == "public"
    assert record_ref["access"]["record"] == "public"
    with app.app_context():
        assert (
            current_community_records_service.search(
                system_identity,
                community_id=community.id,
            ).total
            == 1
        )

        actual = group_data_service.update_group_from_remote(
            system_identity, idp, remote_group_id
        )
        assert actual is not None
        assert community["slug"] in actual

        updated = current_communities.service.read(system_identity, community.id)
        assert updated["access"]["visibility"] == "restricted"
        assert updated["custom_fields"]["kcr:commons_group_visibility"] == "hidden"

        record_reread = current_rdm_records_service.read(
            system_identity, record.id
        ).to_dict()
    assert record_reread["access"]["record"] == "public"
    assert record_reread["access"]["record"] != updated["access"]["visibility"]
