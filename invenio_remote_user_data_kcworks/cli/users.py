# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute
# and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""`user-data users` subgroup for managing user accounts.

- bulk ingestion from JSONL or CSV `ingest-profiles-dump`

Long-running commands (`ingest-profiles-dump`) accept `--background`
to `.delay()` the corresponding Celery task and return immediately
with the task id; without the flag, the work runs synchronously inside
the CLI process.
"""

import re
from pprint import pprint

import click
from flask.cli import with_appcontext
from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_datastore
from invenio_oauthclient.models import UserIdentity
from invenio_users_resources.proxies import current_users_service

from ..proxies import (
    current_remote_user_data_service as user_data_service,
)
from ..tasks import do_ingest_profiles_dump


@click.group(name="users")
def users_cli():
    """Bulk user provisioning and re-pull from the Profiles API."""


@users_cli.command(name="update")
@click.argument("ids", nargs=-1)
@click.option(
    "-g",
    "--groups",
    is_flag=True,
    default=False,
    help=(
        "If true, update groups rather than users. The provided "
        "IDs should be group IDs. (Not yet implemented)"
    ),
)
@click.option(
    "-s",
    "--source",
    default="knowledgeCommons",
    help=(
        "Remote source name. Should be the same as the OAuth/SAML IDP listed in "
        "the UserIdentity table."
    ),
)
@click.option(
    "-e",
    "--by-email",
    is_flag=True,
    default=False,
    help=(
        "Update by email address. If true, the provided ID(s) should be "
        "email addresses."
    ),
)
@click.option(
    "-n",
    "--by-username",
    is_flag=True,
    default=False,
    help=(
        "Update by username. If true, the provided ID(s) should be "
        "usernames from the remote service."
    ),
)
@with_appcontext
def update_user_data(
    ids: list,
    groups: bool,
    source: str,
    by_email: bool,
    by_username: bool,
):
    """Update user or group metadata from the remote data service.

    If IDS are not specified, all records (either users or groups)
    will be updated from the specified remote service.

    IDS can be a list of user or group IDs, or a range of IDs
    separated by a hyphen, e.g. 1-10.

    Parameters:

    ids (list): List of user or group IDs, or ranges of IDs.
    groups (bool): Flag to indicate if groups should be updated.
    source (str): The source of the remote data service. This should
        match the SAML IDP listed in the UserIdentity table.
    by_email (bool): Flag to update by email. If true, the ID(s) should
        be one or more email addresses.
    by_username (bool): Flag to update by remote username. If true,
        the ID(s) should be one or more usernames from the remote
        service.
    """
    print(
        f"Updating {'all ' if len(ids) == 0 else ''}"
        f"{'users' if not groups else 'groups'} "
        f"{','.join(ids)}"
    )
    counter = 0
    successes = []
    unchanged = []
    failures = []
    not_found_remote = []
    not_found_local = []
    timed_out = []
    invalid_responses = []

    sources = ["cilogon", source]

    expanded_ids = []
    for i in ids:
        if re.match(r"\d+-\d+", i):
            start, end = i.split("-")
            for j in range(int(start), int(end) + 1):
                expanded_ids.append(j)
        else:
            expanded_ids.append(i)
    ids = expanded_ids

    ids = sorted(list(set(ids)))

    if len(ids) > 0:
        if not groups:
            for i in ids:
                counter += 1
                if by_email:
                    user = current_datastore.get_user_by_email(i)

                    for source in sources:
                        user_ident = UserIdentity.query.filter_by(
                            id_user=user.id, method=source
                        ).one_or_none()

                        if user_ident:
                            break

                elif by_username:
                    for source in sources:
                        user_ident = UserIdentity.query.filter_by(
                            id=i, method=source
                        ).one_or_none()

                        if user_ident:
                            break
                else:
                    for source in sources:
                        user_ident = UserIdentity.query.filter_by(
                            id_user=int(i), method=source
                        ).one_or_none()

                        if user_ident:
                            break

                if not user_ident:
                    print(f"No remote registration found for {i}")
                    not_found_local.append(i)
                    continue

                update_result = user_data_service.update_user_from_remote(
                    system_identity, user_ident.id_user, source, user_ident.id
                )
                pprint(update_result)
                successes.append(i)
    else:
        users = current_users_service.scan(identity=system_identity)
        for u in users.hits:
            counter += 1

            for source in sources:
                user_ident = UserIdentity.query.filter_by(
                    id_user=u.id, method=source
                ).one_or_none()

                if user_ident:
                    break

            if not user_ident:
                print(f"No remote registration found for {u.id}")
                not_found_local.append(i)
                continue

            try:
                update_result = user_data_service.update_user_from_remote(
                    system_identity, user_ident.id_user, source, user_ident.id
                )
                if not update_result:
                    print(f"Failed to update {u.id}")
                    failures.append(u.id)
                if update_result[1].get("error", "") == "not_found":
                    not_found_remote.append(u.id)
                elif update_result[1].get("error", "") == "timeout":
                    print(f"Timeout updating {u.id}")
                    timed_out.append(u.id)
                elif update_result[1].get("error", "") == "invalid_response":
                    print(f"Invalid response updating {u.id}")
                    invalid_responses.append(u.id)
                elif (
                    len(update_result[1].keys()) == 0 and len(update_result[2]) == 0
                ) and "error" not in update_result[1].keys():
                    print(f"No new data on remote server for {u.id}")
                    unchanged.append(u.id)
                elif update_result:
                    print(f"Updated user {u.id}")
                    pprint(update_result)
                    successes.append(u.id)
            except Exception:
                print(f"Failed to update {u.id}")
                failures.append(u.id)
    print(f"All done updating {counter} {'users' if not groups else 'groups'}")
    if len(successes):
        print(f"Successfully updated {len(successes)} records.")
    if len(unchanged):
        print(f"No updates necessary for {len(unchanged)} records: {unchanged}")
    if len(not_found_local):
        print(
            f"No remote registration found in Invenio for "
            f"{len(not_found_local)} records: {not_found_local}"
        )
    if len(not_found_remote):
        print(
            f"No user found on remote service for {len(not_found_remote)}"
            f"records: {not_found_remote}"
        )
    if len(timed_out):
        print(f"Timeouts occurred for {len(timed_out)} records: {timed_out}")
    if len(invalid_responses):
        print(
            f"Invalid responses returned for "
            f"{len(invalid_responses)} records: "
            f"{invalid_responses}"
        )
    if len(failures):
        print(f"{len(failures)} updates failed for the following records: {failures}")


@users_cli.command(name="ingest-profiles-dump")
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["auto", "jsonl", "usernames"], case_sensitive=False),
    default="auto",
    show_default=True,
    help=(
        "Input format. `jsonl` = one Profiles API response per line "
        "(no API I/O); `usernames` = one KC username per line (live "
        "API fetch per row). `auto` sniffs the first non-blank line."
    ),
)
@click.option(
    "-s",
    "--source",
    default="knowledgeCommons",
    show_default=True,
    help="IDP key passed to the underlying do_user_created task.",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum number of dump rows to process. Default: all.",
)
@click.option(
    "--background",
    is_flag=True,
    default=False,
    help=(
        "Queue the ingest as a Celery task and return immediately with "
        "the task id, instead of running synchronously in the CLI."
    ),
)
@click.option(
    "--rate-per-second",
    type=click.FloatRange(0),
    default=2,
    show_default=True,
    help=(
        "Maximum users per second for `usernames` ingest (live Profiles "
        "API). `0` disables pacing. Fractional values allowed (e.g. "
        "`0.5` = one user every 2s). Ignored for `jsonl` (no API I/O)."
    ),
)
@with_appcontext
def ingest_profiles_dump_cmd(
    filepath: str,
    fmt: str,
    source: str,
    limit: int | None,
    background: bool,
    rate_per_second: float,
):
    r"""Bulk-create / update local users from a Profiles JSONL dump or username CSV.

    Two input shapes are accepted:

    \b
    - `jsonl` — each line is one Profiles API response (no API I/O).
    - `usernames` — one KC username per line (live API fetch per row;
      lazy provisioning fallback gives create-or-update semantics).

    Without `--background`, the work runs synchronously inside the CLI
    process and the final stats dict is printed on completion. With
    `--background`, the same logic is enqueued as a single long-running
    Celery task and the task id is printed immediately.
    """
    if background:
        async_result = do_ingest_profiles_dump.delay(
            filepath,
            fmt=fmt,
            source=source,
            limit=limit,
            rate_per_second=rate_per_second,
        )
        click.echo(f"Queued ingest task: {async_result.id}")
        return
    stats = do_ingest_profiles_dump(
        filepath,
        fmt=fmt,
        source=source,
        limit=limit,
        rate_per_second=rate_per_second,
    )
    click.echo(
        f"Done. rows_seen={stats['rows_seen']}  processed={stats['processed']}  "
        f"skipped={stats['skipped']}  errors={stats['errors']}"
    )


if __name__ == "__main__":
    users_cli()
