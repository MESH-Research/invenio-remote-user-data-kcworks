# Invenio extension for drawing user and groups data from a Remote API.

This extension provides a service and event triggers to draws user and groups data from a remote API associated with a SAML login ID provider. (This is user data that cannot be derived from the SAML response itself at login, but must be pulled separately from an API.)

The service checks to see whether the current user logged in with a SAML provider. If so, it sends an API request to the appropriate remote API associated with that server and stores or updates the user's data on the remote service in the Invenio database.

By default this service is triggered when a user logs in. The service can also be called directly to update user data during a logged-in session, and it can
be triggered by the remote IDP server via a webhook signal.

## User data update content

Responses from the user data update endpoint on the remote SAML idp service should be JSON objects with this shape:

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

## Updating group memberships (InvenioRDM roles)

In addition to recording and updating the user's profile information, it also updates the user's group memberships on the SAML ipd service. If the user is a member of any groups on the remote ID provider, it adds the user to the corresponding groups (InvenioRDM roles) on the Invenio server. If a group role does not exist on the Invenio server, the service creates the role. If a user has been dropped from a group on the remote IDP, they are removed from the corresponding InvenioRDM role.If a user is the last member of a group role and is removed, the service deletes the invenio-accounts role.

The created group names are formed following the pattern "{IDP name}|{remote group name}|{user's role}". So if they are a "member" of the "developers" group on the remote IDP service called "myIDP", they will be assigned to
the InvenioRDM role "myIDP|developers|member".

Note that only InvenioRDM roles that begin with the user's IDP name (like "myIDP|") are included in this synchronization of memberships. Roles without
a bar-delineated IDP prefix are considered locally managed. Users will not
be removed from these roles, even if they do not appear in their memberships
on the remote IDP.

Group membership updates are also one-directional. If a user is added to or removed from a group (role) on the Invenio server, the service does not add the user to the corresponding group on the remote ID provider.

Once a user has been assigned the Invenio role, the user's Invenio Identity object will be updated (on the next request) to provide role Needs corresponding with the user's updated roles.

## Keeping remote data updated

The service is always called when a user logs in (triggered by the identity_changed signal emitted by flask-principal).

## Update webhook

The service can also be triggered by a webhook signal from the remote ID provider. A webhook signal should be sent to the endpoint https://example.org/api/webhooks/idp_data_update/ and the request must include a security token (provided by the Invenio admins) in the request header. This token is set in the REMOTE_USER_DATA_WEBHOOK_TOKEN configuration variable.

The webhook signal should be a POST request with a JSON body. The body should be a JSON object whose top-level keys are

:idp: The name of the remote IDP that is sending the signal. This is a
string that must match one of the keys in the
REMOTE_USER_DATA_API_ENDPOINTS configuration variable.

:updates: A JSON object whose top-level keys are the types of data object that
have been updated on the remote IDP. The value of each key is an
array of objects representing the updated entities. Each of these
objects should include the "id" property, whose value is the entity's
string identifier on the remote IDP. It should also include the
"event" property, whose value is the type of event that is being
signalled (e.g., "updated", "created", "deleted", etc.).

E.g.,

{"idp": "knowledgeCommons",
"updates": {
"users": [{"id": "1234", "event": "updated"},
{"id": "5678", "event": "created"}],
"groups": [{"id": "1234", "event": "deleted"}]
}
}

## Logging

The extension will log each POST request to the webhook endpoint, each signal received, and each task initiated to update the data. These logs will be written to a dedicated log file, `logs/remote_data_updates.log`.

## Configuration

Invenio config variables

```

The extension is configured via the following Invenio config variables:

REMOTE_USER_DATA_API_ENDPOINTS

    A dictionary of remote ID provider names and their associated API information for each kind of user data. The dictionary keys are the names of IDPs. For each ID provider, the value is a dictionary whose keys are the different data categories ("groups", etc.).

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

Environment variables
~~~~~~~~~~~~~~~~~~~~~

The extension also requires the following environment variables to be set:

REMOTE_USER_DATA_WEBHOOK_TOKEN (SECRET!! DO NOT place in config file!!)

    This token is used to authenticate webhook signals received from a remote ID provider. It should be stored in the .env file in the root directory of the Invenio instance or set in the server system environment.

Other environment variables

    The names of the environment variables for the security tokens for API requests to each remote ID provider should be set in the REMOTE_USER_DATA_API_ENDPOINTS configuration variable. The values of these variables should be set in the .env file in the root directory of the Invenio instance or set in the server system environment.
```
