#!/bin/sh
export STANDALONE_DOCS=True
target=${1:-html}
make ${target}
