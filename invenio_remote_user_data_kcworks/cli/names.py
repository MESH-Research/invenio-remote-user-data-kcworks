# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.


"""`user-data names` CLI subgroup for Names vocabulary maintenance.

- per-user re-sync (`sync-now`)
- bulk backfill from published records (`backfill-cited-from-records`)
- inspection (`show`)
- duplicate review / dismissal (`find-duplicates`, `list-duplicates`,
  `merge-orcid-duplicates`, `dismiss-duplicate`, `undismiss-duplicate`,
  `list-dismissed-duplicates`).
- bulk ingestion from JSONL or CSV `ingest-profiles-dump`

Long-running commands (`ingest-profiles-dump`,
`backfill-cited-from-records`, `sync-now`) accept `--background`
to `.delay()` the corresponding Celery task and return immediately
with the task id; without the flag, the work runs synchronously inside
the CLI process.
"""

import re
from datetime import datetime
from pprint import pprint

import click
from flask.cli import with_appcontext
from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_datastore
from invenio_oauthclient.models import UserIdentity

from ..proxies import (
    current_names_sync_service as names_sync_service,
)
from ..tasks import (
    do_backfill_cited_from_records,
    do_find_names_duplicates,
    sync_user_to_names,
)


@click.group(name="names")
def names_cli():
    """KCWorks Names vocabulary maintenance.

    Includes per-user re-sync, bulk backfill from
    published records, inspection helpers, and the duplicate review
    workflow surfaced by the periodic dedupe sweep.
    """


def _resolve_user_id_from_arg(
    arg: str, *, sources: list[str], by_email: bool, by_username: bool
) -> int | None:
    """Resolve a CLI `arg` into a local Invenio user id.

    Mirrors the resolution order of `users update` so `sync-now` and
    `update` accept identical flag semantics.

    Args:
        arg: The user identifier as supplied on the command line.
        sources: IDPs to search in `UserIdentity` (in order).
        by_email: Treat `arg` as an email address.
        by_username: Treat `arg` as a remote-side username
            (`UserIdentity.id`).

    Returns:
        The local user id, or `None` when no matching identity exists.
    """
    if by_email:
        user = current_datastore.get_user_by_email(arg)
        return user.id if user else None
    if by_username:
        for src in sources:
            ident = UserIdentity.query.filter_by(id=arg, method=src).one_or_none()
            if ident is not None:
                return ident.id_user
        return None
    try:
        return int(arg)
    except ValueError:
        return None


@names_cli.command(name="sync-now")
@click.argument("ids", nargs=-1)
@click.option(
    "-s",
    "--source",
    default="knowledgeCommons",
    show_default=True,
    help="Remote source name (matches the UserIdentity.method).",
)
@click.option(
    "-e",
    "--by-email",
    is_flag=True,
    default=False,
    help="Treat each ID as an email address.",
)
@click.option(
    "-n",
    "--by-username",
    is_flag=True,
    default=False,
    help="Treat each ID as a remote-side username.",
)
@click.option(
    "--background",
    is_flag=True,
    default=False,
    help="Queue each upsert as a Celery task instead of running inline.",
)
@with_appcontext
def sync_now_cmd(
    ids: tuple[str, ...],
    source: str,
    by_email: bool,
    by_username: bool,
    background: bool,
):
    """Re-derive each user's Names record from current local profile data.

    Without flags, IDS are treated as local Invenio user ids. Use
    `--by-email` / `--by-username` to resolve in the same way as
    `user-data users update`. No remote Profiles API I/O is performed.

    Raises:
        click.UsageError: When no IDS are supplied.
    """
    if not ids:
        raise click.UsageError("Provide at least one user id (or use --by-* flags).")
    sources = ["cilogon", source]
    for arg in ids:
        user_id = _resolve_user_id_from_arg(
            arg, sources=sources, by_email=by_email, by_username=by_username
        )
        if user_id is None:
            click.echo(f"  - {arg}: no matching user; skipped")
            continue
        if background:
            async_result = sync_user_to_names.delay(user_id)
            click.echo(f"  - {arg} -> user_id={user_id}: queued ({async_result.id})")
            continue
        ok = sync_user_to_names(user_id)
        click.echo(f"  - {arg} -> user_id={user_id}: {'ok' if ok else 'no data'}")


@names_cli.command(name="backfill-cited-from-records")
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum number of published records to scan. Default: all.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Count payloads but skip every Names upsert.",
)
@click.option(
    "--background",
    is_flag=True,
    default=False,
    help="Queue the backfill as a Celery task instead of running inline.",
)
@with_appcontext
def backfill_cited_from_records_cmd(limit: int | None, dry_run: bool, background: bool):
    """Materialize Names records for ORCIDs found in published RDM records.

    Idempotent: USER records get gap-filled, existing CITED stubs get
    refreshed, missing entries get created. Run once per deployment to
    cover pre-component published data.
    """
    if background:
        async_result = do_backfill_cited_from_records.delay(
            limit=limit, dry_run=dry_run
        )
        click.echo(f"Queued backfill task: {async_result.id}")
        return
    stats = do_backfill_cited_from_records(limit=limit, dry_run=dry_run)
    click.echo(
        f"Done. records_scanned={stats['records_scanned']}  "
        f"payloads_seen={stats['payloads_seen']}  "
        f"upserted={stats['upserted']}  errors={stats['errors']}"
    )


@names_cli.command(name="show")
@click.argument("pid_or_orcid")
@with_appcontext
def show_cmd(pid_or_orcid: str):
    """Print a single Names record by PID, or by ORCID iD.

    First tries a direct `read` at the given PID; if that fails, falls
    back to resolving by ORCID scheme (which may yield multiple hits when
    a USER and a CITED stub still co-exist for the same ORCID).

    Raises:
        click.ClickException: When no Names record exists at the given
            PID and no ORCID-resolved hit is found either.
    """
    from invenio_pidstore.errors import PIDDoesNotExistError

    names_service = names_sync_service.names_service
    try:
        item = names_service.read(system_identity, pid_or_orcid)
        pprint(item.to_dict())
        return
    except PIDDoesNotExistError:
        pass
    try:
        resolved = names_service.resolve(
            system_identity, pid_or_orcid, "orcid", many=True
        )
    except PIDDoesNotExistError as exc:
        raise click.ClickException(
            f"No Names record found at PID or ORCID {pid_or_orcid!r}."
        ) from exc
    hits = resolved.to_dict().get("hits", {}).get("hits", [])
    if not hits:
        raise click.ClickException(
            f"No Names record found at PID or ORCID {pid_or_orcid!r}."
        )
    click.echo(f"Found {len(hits)} record(s) carrying ORCID {pid_or_orcid!r}:")
    for h in hits:
        pprint(h)
        click.echo("---")


@names_cli.command(name="merge-orcid-duplicates")
@click.option(
    "--limit",
    type=int,
    default=1000,
    show_default=True,
    help=(
        "Maximum number of identifier-collision buckets returned by the aggregation."
    ),
)
@with_appcontext
def merge_orcid_duplicates_cmd(limit: int):
    """Auto-consolidate Names records that share an ORCID iD.

    Folds non-USER stubs (CITED, untagged harvester records, etc.) that
    share an ORCID with a single USER record into that USER record and
    deletes the stubs. Buckets with more than one USER record (or with
    no USER record) are logged and left for human review via
    `find-duplicates`. Run before `find-duplicates` so the review
    list is not cluttered by pairs that should be auto-merged.
    """
    stats = names_sync_service.merge_orcid_duplicates(limit=limit)
    click.echo(
        f"Merged: {stats['merged']}  "
        f"multi-USER collisions: {stats['multi_user_collisions']}  "
        f"orphan collisions: {stats['orphan_collisions']}  "
        f"errors: {stats['errors']}"
    )
    if stats["multi_user_collisions"] or stats["orphan_collisions"]:
        click.echo(
            "Some ORCID collisions could not be auto-merged; see logs and "
            "run `invenio user-data names find-duplicates` for review."
        )


@names_cli.command(name="find-duplicates")
@click.option(
    "--limit",
    type=int,
    default=None,
    help=(
        "Optional safety cap on family-name buckets collected per "
        "dedup pass. Omit for an exhaustive sweep (default); each "
        "pass paginates until every bucket with >=2 records has "
        "been considered."
    ),
)
@click.option(
    "--since",
    "since",
    type=click.DateTime(),
    default=None,
    help=(
        "Override the cached incremental-sweep bookmark with this "
        "ISO 8601 timestamp. Pairs are kept only if at least one side "
        "was updated at or after `--since`. Without `--since` and "
        "without `--full`, the cached bookmark from the previous run "
        "is used."
    ),
)
@click.option(
    "--full",
    "full_sweep",
    is_flag=True,
    default=False,
    help=(
        "Ignore any cached bookmark and process every candidate pair. "
        "The bookmark is still rewritten on success so the next "
        "incremental run resumes from this sweep's start time."
    ),
)
@click.option(
    "--background",
    is_flag=True,
    default=False,
    help="Queue the find operation as a Celery task instead of running inline.",
)
@with_appcontext
def find_duplicates_cmd(
    limit: int | None,
    since: datetime | None,
    full_sweep: bool,
    background: bool,
):
    """List likely-duplicate Names pairs flagged for human review.

    Run `merge-orcid-duplicates` first so any pair sharing an ORCID
    has been auto-consolidated and does not show up here. Pairs already
    marked dismissed (via `dismiss-duplicate`) are suppressed from the
    output.
    """

    if background:
        async_result = do_find_names_duplicates.delay(
            limit=limit, since=since, full_sweep=full_sweep
        )
        click.echo(
            f"Queued duplicate finding task: {async_result.id}. Possible duplicate pairs "
            "will be marked on the Names vocabulary items concerned."
        )
        return
    rows = names_sync_service.find_duplicate_candidates(
        limit=limit, since=since, full_sweep=full_sweep
    )
    if not rows:
        click.echo("No duplicate candidates above the configured threshold.")
        return
    click.echo(f"Found {len(rows)} candidate pair(s):")
    for r in rows:
        a = r["record_a"]
        b = r["record_b"]
        a_tags = ",".join(a.get("tags") or []) or "untagged"
        b_tags = ",".join(b.get("tags") or []) or "untagged"
        click.echo(
            f"  score={r['score']}  family={r['family_token']}  "
            f'[{a_tags}] {a["id"]} ({a["uuid"]}) "{a["name"]}"  <->  '
            f'[{b_tags}] {b["id"]} ({b["uuid"]}) "{b["name"]}"'
        )
    click.echo(
        "\nTo dismiss a pair (mark as confirmed not-a-duplicate):\n"
        "  invenio user-data names dismiss-duplicate <PID_A> <PID_B>"
    )


@names_cli.command(name="list-duplicates")
@with_appcontext
def list_duplicates_cmd():
    """List every Names pair currently flagged as a possible duplicate.

    Reads the persisted output of `find-duplicates`: every record
    carrying a non-empty `props.possible_duplicates` map contributes
    rows here, deduped to one row per symmetric edge. Use this to
    review what the last `find-duplicates` sweep left for human
    triage, and `dismiss-duplicate` to mark any false positive as
    confirmed not-a-duplicate.
    """
    rows = names_sync_service.list_duplicate_pairs(identity=system_identity)
    if not rows:
        click.echo("No marked duplicate pairs.")
        return
    click.echo(f"{len(rows)} marked duplicate pair(s):")
    for r in rows:
        click.echo(
            f"  score={r['score']} method={r['score_method']}  "
            f'{r["a_pid"]} ({r["a_uuid"]}) "{r["a_name"]}"  <->  '
            f'{r["b_pid"]} ({r["b_uuid"]}) "{r["b_name"]}"'
        )
    click.echo(
        "\nTo dismiss a pair (mark as confirmed not-a-duplicate):\n"
        "  invenio user-data names dismiss-duplicate <PID_A> <PID_B>"
    )


@names_cli.command(name="dismiss-duplicate")
@click.argument("pid_a")
@click.argument("pid_b")
@with_appcontext
def dismiss_duplicate_cmd(pid_a: str, pid_b: str):
    """Mark two Names records as confirmed *not* duplicates of each other.

    Records each record's UUID on the other's
    `props.dismissed_duplicates` list; the candidate finder will then
    skip the pair on subsequent runs. Idempotent.

    Raises:
        click.ClickException: If either PID does not exist or the
            update fails.
    """
    ok = names_sync_service.dismiss_duplicate_pair(
        pid_a, pid_b, identity=system_identity
    )
    if ok:
        click.echo(f"Dismissed duplicate pair: {pid_a} <-> {pid_b}")
    else:
        raise click.ClickException(
            f"Failed to dismiss pair {pid_a} <-> {pid_b}; check the "
            f"application log for details (most likely cause: one of "
            f"the PIDs does not exist)."
        )


@names_cli.command(name="undismiss-duplicate")
@click.argument("pid_a")
@click.argument("pid_b")
@with_appcontext
def undismiss_duplicate_cmd(pid_a: str, pid_b: str):
    """Reverse a previous `dismiss-duplicate` so the pair re-appears.

    Idempotent: calling on a pair that was not dismissed succeeds with
    no changes.

    Raises:
        click.ClickException: If either PID does not exist or the
            update fails.
    """
    ok = names_sync_service.undismiss_duplicate_pair(
        pid_a, pid_b, identity=system_identity
    )
    if ok:
        click.echo(f"Un-dismissed duplicate pair: {pid_a} <-> {pid_b}")
    else:
        raise click.ClickException(
            f"Failed to un-dismiss pair {pid_a} <-> {pid_b}; check the "
            f"application log for details."
        )


@names_cli.command(name="list-dismissed-duplicates")
@with_appcontext
def list_dismissed_duplicates_cmd():
    """List every Names pair currently marked as not-a-duplicate."""
    rows = names_sync_service.list_dismissed_duplicate_pairs(identity=system_identity)
    if not rows:
        click.echo("No dismissed duplicate pairs.")
        return
    click.echo(f"{len(rows)} dismissed duplicate pair(s):")
    for r in rows:
        click.echo(
            f'  {r["a_pid"]} ({r["a_uuid"]}) "{r["a_name"]}"  <->  '
            f'{r["b_pid"]} ({r["b_uuid"]}) "{r["b_name"]}"'
        )
