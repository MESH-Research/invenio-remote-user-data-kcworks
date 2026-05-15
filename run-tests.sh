#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# This file is part of invenio-remote-user-data-kcworks.
# Copyright (C) 2024-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software;
# you can redistribute and/or modify it under the terms of the
# MIT License; see LICENSE file for more details.
#
# Slim standalone test runner for this submodule, modeled on
# invenio-stats-dashboard/run-tests.sh. Drops the doc-build and
# translation-compile steps when their inputs aren't present in
# this package, drops stats-dashboard's patch-application logic
# (this package patches nothing), and uses `ty` for type checking
# (matching the parent KCWorks project). The combined
# `./run-tests.sh` at the repo root is still the canonical CI entry
# point; this script is for fast, iterative, package-local runs.

# Quit on errors
set -o errexit

# Quit on unbound symbols
set -o nounset

# Always bring down docker services
function cleanup() {
  eval "$(uv run docker-services-cli down --env)"
}

# Check if any docker-compose projects are running
function check_docker_compose_running() {
  echo "Checking for running docker-compose projects..."

  # Get list of running containers that might be from docker-compose
  running_containers=$(docker ps --format "table {{.Names}}\t{{.Image}}" | grep -E "(postgres|redis|opensearch|rabbitmq|elasticsearch)" || true)

  if [ -n "$running_containers" ]; then
    echo "Warning: Found potentially conflicting containers running:"
    echo "$running_containers"
    echo ""
    echo "This might cause port conflicts with docker-services-cli."
    echo "Consider stopping any running docker-compose projects before continuing."
    echo ""
    read -p "Do you want to continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "Aborting. Please stop conflicting containers and try again."
      exit 1
    fi
  else
    echo "No conflicting containers detected."
  fi
}

# Check for arguments
# Note: "-k" would clash with "pytest"
keep_services=0
skip_translations=0
pytest_args=()
for arg in $@; do
  # from the CLI args, filter out some known values and forward the rest to "pytest"
  # note: we don't use "getopts" here b/c of some limitations (e.g. long options),
  #       which means that we can't combine short options (e.g. "./run-tests -Kk pattern")
  case ${arg} in
  -K | --keep-services)
    keep_services=1
    ;;
  -S | --skip-translations)
    skip_translations=1
    ;;
  *)
    pytest_args+=(${arg})
    ;;
  esac
done

if [[ ${keep_services} -eq 0 ]]; then
  trap cleanup EXIT
fi

# Extract and compile translations only when this package actually ships a
# semantic-ui translations tree. This package currently has none, so the
# block is a no-op; kept for parity with the parent runner so adding
# translations later doesn't require touching the script.
translations_dir="invenio_remote_user_data_kcworks/assets/semantic-ui/translations"
if [ -d "${translations_dir}" ]; then
  if [[ ${skip_translations} -eq 0 ]]; then
    echo "Extracting translations from python files"
    uv run invenio-cli translations extract
    echo "Updating translations"
    uv run invenio-cli translations update
    echo "Compiling translations"
    uv run invenio-cli translations compile
  else
    echo "Skipping translations compilation"
  fi
else
  echo "No translations directory at ${translations_dir}; skipping translations step"
fi

# Build the documentation only when a docs/ source tree exists.
if [ -d "docs/source/" ]; then
  echo "Building the documentation"
  uv run sphinx-build -b html docs/source/ docs/build/
else
  echo "No docs/source/ directory; skipping documentation build"
fi

# Check for running docker-compose projects before starting services
check_docker_compose_running

# Check if tests/.env exists and set env_file_arg accordingly
if [ -f "tests/.env" ]; then
  env_file_arg="--env-file tests/.env"
  echo "Using tests/.env file for environment variables"
else
  env_file_arg=""
  echo "No tests/.env file found, using default environment"
fi

# Start the services and get their environment variables
echo "Starting the services"
eval "$(uv run ${env_file_arg} docker-services-cli --filepath .venv/lib/python3.12/site-packages/docker_services_cli/docker-services.yml up --db ${DB:-postgresql} --cache ${CACHE:-redis} --search opensearch --mq ${MQ:-rabbitmq} --env)"

# Unset the environment variables that docker-services-cli set so that the values from tests/.env are used instead of those defaults from docker-services.yml
unset SQLALCHEMY_DATABASE_URI
unset INVENIO_SQLALCHEMY_DATABASE_URI

# Install the package in editable mode (needed for pytest-ruff to resolve the
# in-tree source rather than the installed copy).
if ! uv pip show invenio-remote-user-data-kcworks 2>/dev/null | grep -q "Editable project location"; then
  echo "Installing package in editable mode"
  uv pip install -e .
else
  echo "Package already installed as editable, skipping installation"
fi

# Run ty (replaces mypy; settings live under [tool.ty] in pyproject.toml)
echo "Running ty on the invenio_remote_user_data_kcworks directory"
uv run ty check invenio_remote_user_data_kcworks/

# Note: expansion of pytest_args looks like below to not cause an unbound
# variable error when 1) "nounset" and 2) the array is empty.
if [ ${#pytest_args[@]} -eq 0 ]; then
  echo "Running pytest"
  uv run ${env_file_arg} python -m pytest -vv -s --disable-warnings
else
  echo "Running pytest with additional arguments"
  uv run ${env_file_arg} python -m pytest ${pytest_args[@]} -s --disable-warnings
fi

tests_exit_code=$?
exit "$tests_exit_code"
