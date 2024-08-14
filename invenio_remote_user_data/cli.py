import click
from flask.cli import with_appcontext
from invenio_access.permissions import system_identity
from invenio_accounts.models import User
from invenio_accounts.proxies import current_datastore
from invenio_oauthclient.models import UserIdentity
from pprint import pprint
from .proxies import (
    current_remote_user_data_service as user_data_service,
    current_remote_group_data_service as group_data_service,
)


@click.group()
def cli():
    pass


@cli.command(name="update")
@click.argument("ids", nargs=-1)
@click.option(
    "-g",
    "--groups",
    is_flag=True,
    default=False,
    help=("If true, update groups rather than users."),
)
@click.option("-s", "--source", default="knowledgeCommons")
@click.option("-e", "--by-email", is_flag=True, default=False)
@click.option("-n", "--by-username", is_flag=True, default=False)
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

    """
    print(
        f"Updating {'all ' if len(ids) == 0 else ''}{'users' if not groups else 'groups'} {','.join(ids)}"
    )
    if len(ids) > 0:
        if not groups:
            for i in ids:
                if by_email:
                    user = current_datastore.get_user_by_email(i)
                    user_ident = UserIdentity.query.filter_by(
                        id_user=user.id, method=source
                    )
                elif by_username:
                    user_ident = UserIdentity.query.filter_by(
                        id=i, method=source
                    ).one_or_none()
                else:
                    user_ident = UserIdentity.query.filter_by(
                        id_user=i, method=source
                    ).one_or_none()
                if not user_ident:
                    print(f"No remote registration found for {i}")
                    break

                update_result = user_data_service.update_user_from_remote(
                    system_identity, user_ident.id_user, source, user_ident.id
                )
                pprint(update_result)


if __name__ == "__main__":
    cli()
