# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""invenio-jobs JobTypes for Names vocabulary maintenance.

Registered under the `invenio_jobs.jobs` entry point. Operators schedule them
with `invenio kcworks-jobs upsert <task_id> --schedule …` (see
`scripts/setup-services.sh` for the defaults).

Task ids:

- `sync_names_missing_users` — bulk USER backfill (`missing_only=True`)
- `merge_names_orcid_duplicates` — auto-merge ORCID-sharing pairs
- `find_names_duplicates` — soft-duplicate scan for human review
"""

from __future__ import annotations

from invenio_i18n import lazy_gettext as _
from invenio_jobs.jobs import JobType, PredefinedArgsSchema

from .tasks import (
    do_find_names_duplicates,
    do_merge_orcid_duplicates,
    do_sync_all_users_to_names,
)


class SyncNamesMissingUsersJob(JobType):
    """Backfill Names USER records for local accounts that lack one."""

    id = "sync_names_missing_users"
    title = _("Sync missing Names USER records")
    description = _(
        "Walk local KCWorks users and upsert Names USER records for accounts "
        "that have a KC username but no Names PID yet."
    )
    task = do_sync_all_users_to_names
    arguments_schema = None

    @classmethod
    def build_task_arguments(cls, job_obj, since=None, **kwargs):
        """Always run a missing-only, non-dry-run bulk sync.

        Returns:
            Keyword arguments for `do_sync_all_users_to_names`.
        """
        return {"missing_only": True, "dry_run": False}


class MergeNamesOrcidDuplicatesJob(JobType):
    """Auto-merge Names records that share an ORCID iD."""

    id = "merge_names_orcid_duplicates"
    title = _("Merge Names ORCID duplicates")
    description = _(
        "Consolidate Names records that share an ORCID (CITED stubs into "
        "USER records where safe). Does not merge two USER records."
    )
    task = do_merge_orcid_duplicates
    arguments_schema = None

    @classmethod
    def build_task_arguments(cls, job_obj, since=None, **kwargs):
        """Use the service default bucket limit.

        Returns:
            Keyword arguments for `do_merge_orcid_duplicates`.
        """
        return {"limit": 1000}


class FindNamesDuplicatesJob(JobType):
    """Score near-duplicate Names pairs for human review."""

    id = "find_names_duplicates"
    title = _("Find Names duplicate candidates")
    description = _(
        "Scan the Names vocabulary for likely duplicate pairs (similar names "
        "without a safe ORCID merge) and persist them for triage."
    )
    task = do_find_names_duplicates
    arguments_schema = PredefinedArgsSchema

    @classmethod
    def build_task_arguments(cls, job_obj, since=None, **kwargs):
        """Pass the job's `since` bookmark into the soft-duplicate sweep.

        When `since` is unset, invenio-jobs supplies the start of the last
        successful run (incremental sweep). Pass custom args with
        `full_sweep=True` for a full corpus scan.

        Returns:
            Keyword arguments for `do_find_names_duplicates`.
        """
        args: dict = {}
        if since is not None:
            args["since"] = since
        return args
