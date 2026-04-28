# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""CLI commands for user data and Names vocabulary maintenance.

Single top-level group `user-data` (registered via the
`flask.commands` entry point) with two subgroups:

* `users` — bulk user provisioning / re-pull from Profiles
  (`update`, `ingest-profiles-dump`).
* `names` — Names vocabulary maintenance: per-user re-sync
  (`sync-now`), bulk backfill from published RDM records
  (`backfill-cited-from-records`), record inspection (`show`),
  ORCID-based auto-merge (`merge-orcid-duplicates`), and the
  duplicate-review workflow (`find-duplicates`, `list-duplicates`,
  `dismiss-duplicate`, `undismiss-duplicate`,
  `list-dismissed-duplicates`).

Long-running commands (`ingest-profiles-dump`,
`backfill-cited-from-records`, `sync-now`, `find-duplicates`)
accept `--background` to `.delay()` the corresponding Celery task
and return immediately with the task id; without the flag the work
runs synchronously inside the CLI process.
"""

import click

from .names import names_cli
from .users import users_cli


@click.group()
def cli():
    """User and group data updates from remote sources."""


cli.add_command(names_cli)
cli.add_command(users_cli)
