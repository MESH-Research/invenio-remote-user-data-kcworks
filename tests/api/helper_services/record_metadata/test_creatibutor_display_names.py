# Copyright (C) 2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Unit tests for creatibutor `person_or_org.name` rewrite helpers."""

from invenio_remote_user_data_kcworks.utils.record_metadata import (
    rewrite_creatibutor_display_names,
    user_identifier_pairs,
)


def test_user_identifier_pairs_maps_profile_fields():
    """Profile identifier fields map to creatibutor schemes."""
    pairs = user_identifier_pairs(
        {
            "identifier_kc_username": "jdoe",
            "identifier_orcid": "0000-0002-1825-0097",
            "identifier_email": "jdoe@example.org",
            "identifier_other": "ignored",
        }
    )
    assert pairs == [
        ("kc_username", "jdoe"),
        ("orcid", "0000-0002-1825-0097"),
        ("email", "jdoe@example.org"),
    ]


def test_user_identifier_pairs_skips_blank():
    """Blank identifier values are omitted."""
    assert (
        user_identifier_pairs(
            {"identifier_kc_username": "  ", "identifier_orcid": ""}
        )
        == []
    )


def test_rewrite_updates_matching_personal_creatibutors():
    """Matching creator/contributor names become the target display_name."""
    metadata = {
        "creators": [
            {
                "person_or_org": {
                    "type": "personal",
                    "name": "Jane Doe",
                    "identifiers": [
                        {"scheme": "kc_username", "identifier": "jdoe"},
                    ],
                }
            },
            {
                "person_or_org": {
                    "type": "organisational",
                    "name": "Some Org",
                    "identifiers": [
                        {"scheme": "kc_username", "identifier": "jdoe"},
                    ],
                }
            },
        ],
        "contributors": [
            {
                "person_or_org": {
                    "type": "personal",
                    "name": "Doe, J.",
                    "identifiers": [
                        {"scheme": "orcid", "identifier": "0000-0002-1825-0097"},
                    ],
                }
            },
            {
                "person_or_org": {
                    "type": "personal",
                    "name": "Other Person",
                    "identifiers": [
                        {"scheme": "kc_username", "identifier": "other"},
                    ],
                }
            },
        ],
    }

    changed = rewrite_creatibutor_display_names(
        metadata,
        display_name="Doe, Jane",
        id_pairs=[
            ("kc_username", "jdoe"),
            ("orcid", "0000-0002-1825-0097"),
        ],
    )

    assert changed is True
    assert metadata["creators"][0]["person_or_org"]["name"] == "Doe, Jane"
    assert metadata["creators"][1]["person_or_org"]["name"] == "Some Org"
    assert metadata["contributors"][0]["person_or_org"]["name"] == "Doe, Jane"
    assert metadata["contributors"][1]["person_or_org"]["name"] == "Other Person"


def test_rewrite_unchanged_when_already_display_name():
    """No change when matching entries already store display_name."""
    metadata = {
        "creators": [
            {
                "person_or_org": {
                    "type": "personal",
                    "name": "Doe, Jane",
                    "identifiers": [
                        {"scheme": "kc_username", "identifier": "jdoe"},
                    ],
                }
            }
        ]
    }
    changed = rewrite_creatibutor_display_names(
        metadata,
        display_name="Doe, Jane",
        id_pairs=[("kc_username", "jdoe")],
    )
    assert changed is False


def test_rewrite_noop_without_display_or_ids():
    """Missing display_name or id pairs leaves metadata untouched."""
    metadata = {
        "creators": [
            {
                "person_or_org": {
                    "type": "personal",
                    "name": "Jane Doe",
                    "identifiers": [{"scheme": "kc_username", "identifier": "jdoe"}],
                }
            }
        ]
    }
    assert (
        rewrite_creatibutor_display_names(
            metadata, display_name="", id_pairs=[("kc_username", "jdoe")]
        )
        is False
    )
    assert (
        rewrite_creatibutor_display_names(
            metadata, display_name="Doe, Jane", id_pairs=[]
        )
        is False
    )
    assert metadata["creators"][0]["person_or_org"]["name"] == "Jane Doe"
