# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Utility functions for invenio-remote-user-data."""

# import logging
# import os
# from pathlib import Path

# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# formatter = logging.Formatter(
#     "%(asctime)s:RemoteUserDataService:%(levelname)s: %(message)s"
# )
# log_folder = Path(__file__).parent / "logs"
# os.makedirs(log_folder, exist_ok=True)
# file_handler = logging.handlers.RotatingFileHandler(
#     log_folder / "remote_data_updates.log",
#     mode="a",
#     maxBytes=1000000,
#     backupCount=5,
# )
# file_handler.setFormatter(formatter)
# if logger.hasHandlers():
#     logger.handlers.clear()
# logger.addHandler(file_handler)


def update_nested_dict(original, update):
    for key, value in update.items():
        if isinstance(value, dict):
            original[key] = update_nested_dict(original.get(key, {}), value)
        elif isinstance(value, list):
            original.setdefault(key, []).extend(value)
        else:
            original[key] = value
    return original


def diff_between_nested_dicts(original, update):
    """Return the difference between two nested dictionaries."""  # noqa
    diff = {}
    if not original:
        return update
    else:
        for key, value in update.items():
            if isinstance(value, dict):
                diff[key] = diff_between_nested_dicts(
                    original.get(key, {}), value
                )
            elif isinstance(value, list):
                diff[key] = list(set(value) - set(original.get(key, [])))
            else:
                if original.get(key) != value:
                    diff[key] = value
        diff = {k: v for k, v in diff.items() if v}
        return diff
