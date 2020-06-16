# IGSC FU Documentation

## Setup Linux

Source the setup-env.sh directory to setup python virtual environment

`$ source ./setup-env.sh`

To leave the environment user python venv deactivate

`$ deactivate`

## Compilation

To docs are not created on default to enable building docs from cmake set
BUILD_DOCS to ON

`$cmake -DBUILD_DOCS:BOOL=ON`

## Standalone build

For CI purposes there is a standalone version documentation creation using make.

`$export STANDALONE_DOCS=1`

`$make html`
