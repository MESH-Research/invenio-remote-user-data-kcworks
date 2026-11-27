# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""`user-data records` subgroup for creatibutor username / display_name rewrites.

Commands:

- `update_contributors_username` — rewrite `kc_username` on creators/contributors
- `backfill-creatibutor-names` — set creatibutor `person_or_org.name` to each
  user's profile `display_name`
"""

import click
from flask.cli import with_appcontext

from ..proxies import current_record_creatibutor_sync_service
from ..tasks import rewrite_records_for_kc_username_change


@click.group(name="records")
def records_cli():
    """Rewrite creatibutor identifiers and display names on RDM records."""


@records_cli.command("update_contributors_username")
@click.option(
    "--old-kc-username",
    "-o",
    required=True,
    help=(
        "KC username currently stored on matching creator/contributor metadata entries."
    ),
)
@click.option(
    "--new-kc-username",
    "-n",
    required=True,
    help="KC username to write in place of the old value.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help=(
        "List published and draft record IDs that would be updated, without "
        "writing changes."
    ),
)
@click.option(
    "--background",
    is_flag=True,
    default=False,
    help=(
        "Queue the rewrite on Celery and return immediately with the task id, "
        "instead of running synchronously in the CLI."
    ),
)
@with_appcontext
def update_contributors_username_command(
    old_kc_username: str,
    new_kc_username: str,
    dry_run: bool,
    background: bool,
) -> None:
    """Update kc_username on record creators and contributors.

    For account merge/migration: updates metadata citations from
    `--old-kc-username` to `--new-kc-username`. Does not change record
    ownership or Names vocabulary entries. Uses
    `rewrite_records_for_kc_username_change` with Names pruning disabled.

    Raises:
        click.UsageError: When usernames are empty or identical, or when
            `--dry-run` is combined with `--background`.
        click.Abort: When the rewrite reports phase errors.
    """
    old_kc_username = old_kc_username.strip()
    new_kc_username = new_kc_username.strip()
    if not old_kc_username or not new_kc_username:
        raise click.UsageError(
            "Both --old-kc-username and --new-kc-username are required."
        )
    if old_kc_username == new_kc_username:
        raise click.UsageError("Old and new KC usernames must differ.")
    if dry_run and background:
        raise click.UsageError("--dry-run cannot be used with --background.")

    if dry_run:
        click.echo(
            f"Records that would update kc_username "
            f"{old_kc_username!r} -> {new_kc_username!r}:"
        )
        matches = (
            current_record_creatibutor_sync_service.find_record_ids_for_kc_username(
                old_kc_username
            )
        )
        total = 0
        for phase in ("published", "drafts"):
            record_ids = matches.get(phase) or []
            total += len(record_ids)
            click.echo(f"{phase} ({len(record_ids)} record(s)):")
            for record_id in record_ids:
                click.echo(f"  {record_id}")
        click.echo(f"Total: {total} record(s) would be updated.")
        return

    click.echo(f"Rewriting kc_username {old_kc_username!r} -> {new_kc_username!r}")

    if background:
        async_result = rewrite_records_for_kc_username_change.delay(
            0,
            old_kc_username,
            new_kc_username,
            prune_names=False,
        )
        click.echo(f"Queued rewrite task: {async_result.id}")
        return

    summary = rewrite_records_for_kc_username_change(
        0,
        old_kc_username,
        new_kc_username,
        prune_names=False,
    )
    records = summary.get("records") or {}
    for phase in ("published", "drafts"):
        phase_stats = records.get(phase) or {}
        click.echo(
            f"{phase}: matched={phase_stats.get('matched', 0)} "
            f"updated={phase_stats.get('updated', 0)} "
            f"failed={phase_stats.get('failed', 0)}"
        )
    if summary.get("errors"):
        click.secho(f"Phase errors: {summary['errors']}", fg="red")
        raise click.Abort()


@records_cli.command("backfill-creatibutor-names")
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Report what would change without writing.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Stop after updating this many records (published + drafts).",
)
@click.option(
    "--user-id",
    type=str,
    default=None,
    help="Only process creatibutors for this local user id.",
)
@with_appcontext
def backfill_creatibutor_names_command(
    dry_run: bool,
    limit: int | None,
    user_id: str | None,
) -> None:
    """Set creatibutor `person_or_org.name` to each user's `display_name`.

    Matches personal creators/contributors by profile identifiers
    (`kc_username`, `orcid`, `email`) only. Requires `display_name` to
    already be set (run `invenio user-data users backfill-display-names`
    first if needed). Uses the same record rewrite shell as
    `update_contributors_username`.
    """
    stats = (
        current_record_creatibutor_sync_service.backfill_creatibutor_display_names(
            dry_run=dry_run,
            limit=limit,
            user_id=user_id,
        )
    )
    mode = "dry-run" if dry_run else "applied"
    click.echo(
        f"Done ({mode}). "
        f"users_scanned={stats['users_scanned']}  "
        f"users_eligible={stats['users_eligible']}  "
        f"records_updated={stats['records_updated']}  "
        f"records_unchanged={stats['records_unchanged']}  "
        f"records_failed={stats['records_failed']}  "
        f"errors={stats['errors']}"
    )
