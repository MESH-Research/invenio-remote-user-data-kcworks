# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""CLI commands for user data-related actions."""

import re
from pprint import pprint

import click
from flask.cli import with_appcontext
from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_datastore
from invenio_oauthclient.models import UserIdentity
from invenio_users_resources.proxies import current_users_service

from .proxies import (
    current_names_sync_service as names_sync_service,
)
from .proxies import (
    current_remote_user_data_service as user_data_service,
)


@click.group()
def cli():
    """User and group data updates from remote source."""


@cli.command(name="update")
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
    """
    Update user or group metadata from the remote data service.

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

    Returns:

    None
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

    # handle ranges
    expanded_ids = []
    for i in ids:
        if re.match(r"\d+-\d+", i):
            start, end = i.split("-")
            for j in range(int(start), int(end) + 1):
                expanded_ids.append(j)
        else:
            expanded_ids.append(i)
    ids = expanded_ids

    # eliminate duplicates
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


@click.group()
def names_cli():
    """KCWorks Names vocabulary maintenance commands.

    Includes utilities for reviewing fuzzy-matched duplicate candidates
    surfaced by the periodic dedupe sweep, and for dismissing /
    un-dismissing pairs that an operator has confirmed are *not*
    duplicates. Dismissals are recorded by UUID on both sides of the
    pair (in ``Name.props.dismissed_duplicates``) so the candidate
    finder will not surface the same pair again until reversed.
    """


@names_cli.command(name="merge-orcid-duplicates")
@click.option(
    "--limit",
    type=int,
    default=1000,
    show_default=True,
    help=(
        "Maximum number of identifier-collision buckets returned by "
        "the aggregation."
    ),
)
@with_appcontext
def merge_orcid_duplicates_cmd(limit: int):
    """Auto-consolidate Names records that share an ORCID iD.

    Folds non-USER stubs (CITED, untagged harvester records, etc.) that
    share an ORCID with a single USER record into that USER record and
    deletes the stubs. Buckets with more than one USER record (or with
    no USER record) are logged and left for human review via
    ``find-duplicates``. Run before ``find-duplicates`` so the review
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
            "run `invenio kcworks-names find-duplicates` for review."
        )


@names_cli.command(name="find-duplicates")
@click.option(
    "--limit",
    type=int,
    default=1000,
    show_default=True,
    help=(
        "Maximum number of family-name buckets returned by the "
        "aggregation. Each bucket can yield multiple pairs."
    ),
)
@with_appcontext
def find_duplicates_cmd(limit: int):
    """List likely-duplicate Names pairs flagged for human review.

    Run ``merge-orcid-duplicates`` first so any pair sharing an ORCID
    has been auto-consolidated and does not show up here. Pairs already
    marked dismissed (via ``dismiss-duplicate``) are suppressed from the
    output.
    """
    rows = names_sync_service.find_duplicate_candidates(limit=limit)
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
            f"[{a_tags}] {a['id']} ({a['uuid']}) \"{a['name']}\"  <->  "
            f"[{b_tags}] {b['id']} ({b['uuid']}) \"{b['name']}\""
        )
    click.echo(
        "\nTo dismiss a pair (mark as confirmed not-a-duplicate):\n"
        "  invenio kcworks-names dismiss-duplicate <PID_A> <PID_B>"
    )


@names_cli.command(name="dismiss-duplicate")
@click.argument("pid_a")
@click.argument("pid_b")
@with_appcontext
def dismiss_duplicate_cmd(pid_a: str, pid_b: str):
    """Mark two Names records as confirmed *not* duplicates of each other.

    Records each record's UUID on the other's
    ``props.dismissed_duplicates`` list; the candidate finder will then
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
    """Reverse a previous ``dismiss-duplicate`` so the pair re-appears.

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
    rows = names_sync_service.list_dismissed_duplicate_pairs(
        identity=system_identity
    )
    if not rows:
        click.echo("No dismissed duplicate pairs.")
        return
    click.echo(f"{len(rows)} dismissed duplicate pair(s):")
    for r in rows:
        click.echo(
            f"  {r['a_pid']} ({r['a_uuid']}) \"{r['a_name']}\"  <->  "
            f"{r['b_pid']} ({r['b_uuid']}) \"{r['b_name']}\""
        )


if __name__ == "__main__":
    cli()
