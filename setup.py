from setuptools import setup, find_packages

setup(
    name="invenio-remote-user-data-kcworks",
    packages=find_packages(where="invenio_remote_user_data_kcworks"),
    package_dir={"": "invenio_remote_user_data_kcworks"},
    install_requires=[
        "invenio-records-resources @ file://./invenio_remote_user_data_kcworks/dependencies/invenio-records-resources",
        "invenio-communities @ file://./invenio_remote_user_data_kcworks/dependencies/invenio-communities",
        "invenio-group-collections @ file://./invenio_remote_user_data_kcworks/dependencies/invenio-group-collections",
        "celery",
        "click",
        "deepdiff",
        "invenio-app-rdm[opensearch2]<13.0.0",
        "invenio-queues",
        "invenio-search",
        "invenio-utilities-tuw",
        "opensearch-dsl",
    ],
)
