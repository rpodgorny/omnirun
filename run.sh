#!/bin/sh
set -e -x
pipenv install
exec pipenv run python -m omnirun "$@"
