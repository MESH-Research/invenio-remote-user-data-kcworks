# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Local user profile name helpers and display_name backfill.

Owns profile `display_name` / name-parts reads and writes that belong with
remote user-data sync (not the main `kcworks` package).
"""

import json
from typing import Any, cast

from invenio_accounts.models import User, UserProfileDict
from invenio_accounts.proxies import current_accounts

from ..utils.names import get_full_name, get_full_name_inverted


class UserProfileService:
    """Service for updating and reading user profile name fields."""

    @classmethod
    def get_user_name_variants(
        cls, user_id: str, user_profile: UserProfileDict
    ) -> dict[str, Any]:
        """Get the name variants for a user.

        This returns the user's full name in standard order, along with the
        inverted version of the name (as in last-name-first bibliographic
        order). If the user has locally customized name parts, those will be
        used first but variants will also be included using the name parts as
        provided by external authentication (OAuth).

        Args:
            user_id: The ID of the user.
            user_profile: The user profile object.

        Returns:
            dict: A dictionary containing the name variants for the user
            (`full_name`, `display_name`, and optionally `name_aliases`).

        Raises:
            ValueError: If user_id or user_profile is invalid.
        """
        if not user_profile:
            if not user_id:
                raise ValueError(
                    "User ID or user profile object is required to get name variants"
                )
            user_profile = current_accounts.datastore.get_user_by_id(
                user_id
            ).user_profile

        stored_full = (user_profile.get("full_name") or "").strip()
        stored_display = (user_profile.get("display_name") or "").strip()
        parts = user_profile.get("name_parts_local") or user_profile.get("name_parts")
        composed_full = composed_display = ""
        if parts:
            try:
                composed_full = get_full_name(parts, json_input=True).strip()
                composed_display = get_full_name_inverted(parts, json_input=True).strip()
            except ValueError:
                pass

        full_name = stored_full or composed_full
        display_name = stored_display or composed_display
        result: dict[str, Any] = {}
        if full_name:
            result["full_name"] = full_name
        if display_name:
            result["display_name"] = display_name

        primary = {full_name, display_name}
        aliases = [
            value
            for value in (composed_full, composed_display)
            if value and value not in primary
        ]
        if aliases:
            result["name_aliases"] = aliases
        return result

    @classmethod
    def compute_display_name_from_profile(
        cls, user_profile: UserProfileDict | dict[str, Any]
    ) -> str:
        """Compose inverted `display_name` from local-or-remote name parts.

        Prefers `name_parts_local` over `name_parts`, matching Names sync and
        remote profile sync.

        Args:
            user_profile: The user's profile dict.

        Returns:
            Inverted display string, or `""` when parts are missing/invalid.
        """
        raw = user_profile.get("name_parts_local") or user_profile.get("name_parts")
        if not raw:
            return ""
        try:
            return get_full_name_inverted(raw, json_input=isinstance(raw, str))
        except (TypeError, ValueError, json.JSONDecodeError):
            return ""

    @classmethod
    def update_local_name_parts(cls, user_id: str, name_parts: dict[str, Any]) -> User:
        """Update the locally edited name parts for the specified user.

        Also refreshes persisted `display_name` from the new parts.

        Args:
            user_id: The ID of the user to update.
            name_parts: A dictionary containing the name parts to update.

        Returns:
            User: The updated user object.

        Raises:
            ValueError: If the user ID is not found.
        """
        user_object = current_accounts.datastore.get_user_by_id(user_id)
        if not user_object:
            raise ValueError(f"User with ID {user_id} not found")
        profile = user_object.user_profile
        profile["name_parts_local"] = json.dumps(name_parts)
        try:
            inverted = get_full_name_inverted(name_parts)
        except ValueError:
            inverted = ""
        if inverted:
            profile["display_name"] = inverted
        user_object.user_profile = profile
        current_accounts.datastore.commit()
        return user_object

    @classmethod
    def backfill_display_names(
        cls,
        *,
        dry_run: bool = False,
        force: bool = False,
        limit: int | None = None,
        sync_names: bool = False,
        commit_every: int = 100,
    ) -> dict[str, int]:
        """Backfill persisted `user_profile.display_name` from name parts.

        Walks local users and, for each with usable `name_parts_local` or
        `name_parts`, writes the inverted form from
        `compute_display_name_from_profile`. By default only fills empty
        `display_name`; pass `force=True` to recompute and overwrite.

        When `sync_names=True`, also upserts the user's Names vocabulary
        entry from the (possibly updated) profile so
        `props.display_name` stays aligned.

        Args:
            dry_run: When `True`, count would-be writes without committing.
            force: When `True`, overwrite existing non-empty `display_name`.
            limit: Stop after this many profile updates (or would-be updates).
            sync_names: When `True` and not `dry_run`, call Names upsert
                for each updated user.
            commit_every: Commit DB session every N profile writes.

        Returns:
            Stats: `users_scanned`, `updated`, `skipped_has_display`,
            `skipped_no_parts`, `unchanged`, `names_synced`, `names_errors`,
            `errors`.
        """
        from invenio_db import db

        from ..proxies import current_names_sync_service

        stats = {
            "users_scanned": 0,
            "updated": 0,
            "skipped_has_display": 0,
            "skipped_no_parts": 0,
            "unchanged": 0,
            "names_synced": 0,
            "names_errors": 0,
            "errors": 0,
        }
        pending_writes = 0

        for user in User.query.order_by(User.id).yield_per(200):
            stats["users_scanned"] += 1
            try:
                profile = dict(user.user_profile or {})
                computed = cls.compute_display_name_from_profile(profile)
                if not computed:
                    stats["skipped_no_parts"] += 1
                    continue

                existing = (profile.get("display_name") or "").strip()
                if existing and not force:
                    stats["skipped_has_display"] += 1
                    continue
                if existing == computed:
                    stats["unchanged"] += 1
                    continue

                if limit is not None and stats["updated"] >= limit:
                    break

                if not dry_run:
                    profile["display_name"] = computed
                    user.user_profile = profile
                    pending_writes += 1
                    if pending_writes >= commit_every:
                        db.session.commit()
                        pending_writes = 0

                    if sync_names:
                        try:
                            result = current_names_sync_service.upsert_name_for_user(
                                user
                            )
                            if result is not None:
                                stats["names_synced"] += 1
                        except Exception:  # noqa: BLE001 - counted, not propagated
                            stats["names_errors"] += 1

                stats["updated"] += 1

            except Exception:  # noqa: BLE001 - counted, not propagated
                stats["errors"] += 1

        if not dry_run and pending_writes:
            db.session.commit()

        return stats

    @classmethod
    def read_local_name_parts(cls, user_id: str) -> dict[str, Any]:
        """Read the locally edited name parts for a user.

        Args:
            user_id: The ID of the user.

        Returns:
            dict: The locally edited name parts for the user.

        Raises:
            ValueError: If the user ID is not found.
        """
        user_object = current_accounts.datastore.get_user_by_id(user_id)
        if not user_object:
            raise ValueError(f"User with ID {user_id} not found")
        return cast(
            dict[str, Any],
            json.loads(user_object.user_profile.get("name_parts_local", "{}")),
        )
