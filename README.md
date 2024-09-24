# Invenio Remote User Data Service for Knowledge Commons Works

Version 0.5.6-beta0

* Beta release *

This extension for the Knowledge Commons Works installation of InvenioRDM provides a service to draw user and groups data from a remote service associated with a SAML login ID provider. This is user data that cannot be derived from the SAML response itself at login, but must be pulled separately from an API endpoint exposed by the same service. This extension assumes the existence of two API endpoints exposed by the remote service: one for user data and one for group data.

Although this extension was developed for the Knowledge Commons Works installation of InvenioRDM, it could be adapted to other installations of InvenioRDM or other remote services. Most of the changes needed would be in the integration of group collection memberships via the `invenio_group_collections_kcworks` extension.

## Linking Invenio roles and collections with remote service groups

This extension assumes that the `invenio_group_collections` extension is installed to allow Invenio collections (communities) to be linked with groups on the remote service. The extension assumes that Invenio users are assigned membership in these group collections based on their membership in groups on the remote service. To facilitate this, Invenio roles are created for each group collection when the collection is created. These correspond to the membership categories used by the remote service: "member", "admin", or whatever. The Invenio roles are named according to the pattern "{IDP name}---{slug for the group's Invenio collection}|{remote group ID}|{Invenio community permission role}".

If a user's data update includes membership in a remote group, that group may or may not have already created a collection in Invenio. If the group does have a corresponding collection, then the Invenio permissions roles will already exist. The user is simply added to the appropriate role. If the group has not yet created an Invenio collection, this service does not create the collection itself. Instead, it only creates the Invenio roles corresponding to remote group's membership categories, and adds the group's members to the appropriate roles. When and if the group creates a collection, the roles will already be in place and the group members can be assigned varying permission levels based on their role.

For example, if a user is a "member" of the "developers" group (id "12345") on the remote service called "myCommons", the user will be assigned to the role `myCommons---developers|12345|member`.

Note: The Invenio roles for a group are only created by this extension individually, during user data updates. No roles are created if a group metadata update is triggered, even if the group has not yet created a collection. This is because we do not know the remote group's categories of membership until we receive a user data update that includes membership in that group.

Note: It is possible to encounter name collisions in group collection slugs when we try to create a slug from the group's human readable name. This can happen where groups on different remote services have the same name, or when a group tries to create a group collection after having deleted an earlier one. In these cases, the `invenio_group_collections` extension automatically adds a unique suffix to the slug. This suffix is a number that increments by one each time a new collection is created with the same base slug. We do not attempt to resolve these collisions in this extension. Instead, we simply create the roles with the base slug without the disambiguation suffix. This ensures that group members' permissions are carried with them if a group deletes a collection and recreates a new one. The inclusion of the remote group ID in the role name ensures that the role name is unique to the remote group.

## Triggering updates

The service's update operations are triggered in two ways: automatically when a user logs in, and manually via a webhook signal sent from the remote service.

### Automatic update at login

When a user logs in, the `invenio_remote_user_data_kcworks` extension checks to see whether the current user logged in with a SAML provider. If so, it sends an API request to the appropriate remote API associated with that remote service (configured via a variable in the instance's `invenio.cfg` file) and stores or updates the user's data from the remote service in the user's Invenio account metadata.

Only user metadata updates take place automatically at login. These include updates to the user's group memberships on the remote service, but this user update operation does not update any of the metadata for the groups themselves. Group metadata updates are only triggered by the webhook signal.

### Manual update via webhook signal

Updates operations can also be triggered by the remote service via a webhook signal sent to the `/api/webhooks/user_data_update` endpoint. This signal is a minimalist JSON object simply indicating that updates to one or more users or groups have taken place on the remote service. This extension then sends API requests to the remote service to retrieve the updated data, and it updates the corresponding Invenio user accounts and group collections (communities).

A user's group membership information is updated whenever that user's remote metadata is updated. But

## The remote service's user data API

Responses from the user data update endpoint on the remote service should be JSON objects with this shape:

    ```json
    {
        "username": "myuser",
        "email": "myuser@msu.edu",
        "name": "Jane User",
        "first_name": "Jane",
        "last_name": "User",
        "institutional_affiliation": "Michigan State University",
        "groups": [
            {"id": 123456, "name": "Digital Humanists", "role": "member"},
            {"id": 12131415, "name": "MSU test group", "role": "admin"},
        ],
        "orcid": "123-456-7891",
        "preferred_language": "en",
        "time_zone": "UTC"
    }
    ```

None of these keys are required except "username". If "preferred_language" is provided it should be a ???

If "time_zone" is provided it should be ???

## The remote service's group metadata API

The expected response from the remote service's group metadata API is described in the documentation for the `invenio_group_collections` module. It should be a JSON object. Although other properties are expected by other modules, this extension only requires the following properties in the response object:

    ```json
    {
        "id": 123456,
        "name": "My group name",
        "upload_roles": ["member", "admin"],
        "moderate_roles": ["admin"],
    }
    ```

## Updating group memberships (InvenioRDM roles)

In addition to recording and updating the user's profile information, it also updates the user's group memberships on the remote service as described above.

Note: only InvenioRDM roles that begin with the user's SAML or oauth IDP name, followed by three dashes (like "myCommons---") are included in this synchronization of memberships. Roles without such an IDP prefix are considered locally managed. Users will not
be removed from these roles, even if they do not appear in their memberships on the remote service.

Group membership updates are also one-directional. If a user is added to or removed from a group (role) on the Invenio server, the service does not add the user to the corresponding group on the remote ID provider.

Once a user has been assigned the Invenio role, the user's Invenio Identity object will be updated (on the next request) to provide role Needs corresponding with the user's updated roles.

## Handling group deletions

If a group is deleted on the remote service, the extension will remove the corresponding Invenio collection (community) and all of the roles associated with that group. The extension will also remove all of the users from the roles associated with that group.

In some cases, though, the group may be deleted on the remote service but the Invenio collection may still exist. In this case, the extension will "divorce" the collection from the remote group. This procedure involves:

1. Assigning all of the group members individual membership in the Invenio collection with the appropriate permission level: "reader", "curator", or "manager", based on the user's role in the group on the remote service.
2. Deleting the roles associated with the group. This will remove the users from the roles, but since the users are now individual members of the collection, they will still have the appropriate permissions.
3. Removing the group's metadata from the Invenio collection.

This procedure allows the Invenio collection to continue to exist and function, even if the remote group has been deleted. If the group collection managers wish to delete the Invenio collection as well, this should be done as normal through the Invenio interface or the `communities` REST API endpoint.

## Sending update notices to the webhook

The service can also be triggered by a webhook signal from the remote ID provider. A webhook signal should be sent to the endpoint https://example.org/api/webhooks/user_data_update/ and the request must include a security token (provided by the Invenio admins) in the request header. This token is set in the REMOTE_USER_DATA_WEBHOOK_TOKEN configuration variable.

The webhook signal should be a POST request with a JSON body. The body should be a JSON object whose top-level keys are

:idp: The name of the registered IDP for the remote service that is sending the
signal. This is a string that must match one of the keys in the
REMOTE_USER_DATA_API_ENDPOINTS configuration variable.

:updates: A JSON object whose top-level keys are the types of data object that
have been updated on the remote service. The value of each key is an
array of objects representing the updated entities. Each of these
objects should include the "id" property, whose value is the entity's
string identifier on the remote service. It should also include the
"event" property, whose value is the type of event that is being
signalled (e.g., "updated", "created", "deleted", etc.).

E.g.,

```python
{
    "idp": "knowledgeCommons",
    "updates": {
        "users": [{"id": "1234", "event": "updated"},
                  {"id": "5678", "event": "created"}],
        "groups": [{"id": "1234", "event": "deleted"}]
    }
}
```

## Logging

The extension will log each POST request to the webhook endpoint, each signal received, and each task initiated to update the data. These logs will be written to a dedicated log file, `logs/remote_data_updates.log`.

## Configuration

### Invenio config variables

The extension is configured via the following Invenio config variables:

REMOTE_USER_DATA_API_ENDPOINTS

    A dictionary of remote ID provider names and their associated API information for each kind of user data. The dictionary keys are the names of IDPs registered for remote services. For each ID provider, the value is a dictionary whose keys are the different data categories ("groups", etc.) configured to be updated by the corresponding service.

    For each kind of user data, the value is again a dictionary with these keys:

    :remote_endpoint: the URL for the API endpoint where that kind of data can
                      be retrieved, including a placeholder (the string "{placeholder}" for the user's identifier in the API request.:
                      e.g., "https://example.com/api/user/{placeholder}"

    :remote_identifier: the Invenio user property to be used as an identifier
                        in the API request (e.g., "id", "email", etc.)

    :remote_method: the method for the request to the remote API

    :token_env_variable_label: the label used for the environment variable
                               that will hold the security token required by
                               the request. The token should be stored in the
                               .env file in the root directory of the Invenio
                               instance or set in the server system environment.

REMOTE_USER_DATA_MQ_EXCHANGE

    The configuration for the message queue exchange used to trigger the background update calls. Default is a direct exchange with transient delivery mode (in-memory queue).

### Environment variables

The extension also requires the following environment variables to be set:

REMOTE_USER_DATA_WEBHOOK_TOKEN (SECRET!! DO NOT place in config file!!)

    This token is used to authenticate webhook signals received from a remote ID provider. It should be stored in the .env file in the root directory of the Invenio instance or set in the server system environment.

Other environment variables

    The names of the environment variables for the security tokens for API requests to each remote ID provider should be set in the REMOTE_USER_DATA_API_ENDPOINTS configuration variable. The values of these variables should be set in the .env file in the root directory of the Invenio instance or set in the server system environment.

## Developing this Extension

### Versioning

This project uses semantic versioning with a pre-release tag where appropriate. (For an explanation of semantic versioning, see [semver.org](https://semver.org/) and [this Medium article](https://medium.com/@jteodoro/gently-introduction-to-semantic-versioning-f4e015956c8c).) Alpha and beta releases are indicated by the presence of an "-alpha1" or "-beta1" suffix to the version number.

#### Updating the version number

The version number is managed by the bumpver tool, which is configured in the pyproject.toml file. To update to a new major version (a breaking change, not backwards compatible), run

```shell
pipenv run bumpver update --major
```

To update to a new minor version (a new feature, backwards compatible), run

```shell
pipenv run bumpver update --minor
```

To update to a new patch version (a bug fix, backwards compatible), run

```shell
pipenv run bumpver update --patch
```

To update to a new alpha or beta version, run

```shell
pipenv run bumpver update --tag
```
