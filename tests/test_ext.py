from flask import Flask
from invenio_remote_user_data_kcworks import (
    InvenioRemoteUserData,
)


def test_version(app):
    """Test version import."""
    from invenio_remote_user_data_kcworks import (
        __version__,
    )

    assert __version__


def test_init(app):
    """Test extension initialization."""
    dummy_app = Flask("testapp")
    ext = InvenioRemoteUserData(dummy_app)
    assert "invenio-remote-user-data-kcworks" in dummy_app.extensions

    dummy_app = Flask("testapp")
    ext = InvenioRemoteUserData()
    assert "invenio-remote-user-data-kcworks" not in dummy_app.extensions
    ext.init_app(dummy_app)
    assert "invenio-remote-user-data-kcworks" in dummy_app.extensions

    assert "invenio-remote-user-data-kcworks" in app.extensions
    assert app.extensions["invenio-remote-user-data-kcworks"].service
