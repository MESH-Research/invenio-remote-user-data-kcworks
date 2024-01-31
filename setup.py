# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 MESH Research
#
# invenio-remote-user-data is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.

"""Extension to draw user data into InvenioRDM from a remote source"""

from setuptools import find_packages, setup

readme = open("README.md").read()
history = ""
# history = open("CHANGES.md").read()

install_requires = [
    "click>=7.0",
    "invenio-app-rdm",
    "invenio-search",
    "opensearch-dsl",
    "invenio-utilities-tuw",
]

tests_require = [
    "pytest>=7.3.2",
    "pytest-invenio",
    "pytest-runner",
    "requests-mock",
]

dev_requires = [
    "check-manifest",
    "pipenv",
    "pip-tools",
    "pytest>=7.3.2",
    "pytest-invenio",
    "pytest-runner",
    "requests-mock",
]

extras_require = {"tests": tests_require, "dev": dev_requires}

extras_require["all"] = []
for reqs in extras_require.values():
    extras_require["all"].extend(reqs)

packages = find_packages(
    include=["invenio_remote_user_data", "invenio_remote_user_data.*"]
)

setup(
    name="invenio-remote-user-data",
    description=__doc__,
    long_description=readme + "\n\n" + history,
    long_description_content_type="text/markdown",
    keywords="invenio inveniordm users",
    license="MIT",
    author="Mesh Research",
    author_email="scottia4@msu.edu",
    url="https://github.com/MESH-Research/invenio-remote-user-data",
    packages=packages,
    include_package_data=True,
    platforms="any",
    install_requires=install_requires,
    extras_require=extras_require,
    tests_require=tests_require,
    setup_requires=["pytest-runner"],
    classifiers=[
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
