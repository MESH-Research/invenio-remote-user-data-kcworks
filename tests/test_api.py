
"""Tests of API client calls for invenio-remote-user-data-kcworks."""

def test_api_send_profiles_logout(running_app, db, requests_mock):
    """Test the profiles logout signal sending on KCWorks logout."""
    app = running_app.app

    u = user_factory(
        email=user_data_set["user1"]["email"],
        token=True,
    )
    user = u.user
    token = u.allowed_token

    metadata = record_metadata(
        metadata_in=self.metadata_source,
        owner_id=user.id,
    )

    # log user in with client
    with app.test_client() as client:
        logged_in_client = client_with_login(client, user)

    # mock response from profiles endpoint
    base_url = app.config.get("IDMS_BASE_API_URL")
    mock_profiles = requests_mock.get(
        f"{base_url}actions/logout",
        json={
            "user_name":
            },
    )
    # assert that the endpoint was called

    # assert that it was called with the correct payload

def test_api_send_profiles_logout_500():
    """Test the profiles logout signal sending when request fails.

    A request error should be logged but not interrupt the logout.
    """
    pass

test_api_send_profiles_logout_400():
    """Test the profiles logout signal sending when response unsuccessful.

    A request error should be logged but not interrupt the logout.
    """
    pass

"""
```http
GET https://localhost/api/webhooks/users/logout
````
"""
