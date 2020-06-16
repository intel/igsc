#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2020 Intel Corporation

DIR="${BASH_SOURCE[0]}"
NAME=$(basename -- "$0")
if [ "X$NAME" "==" "Xsetup-env.sh" ]; then
    echo "Source this file (do NOT execute it!)."
    exit
fi

[ -x py-sphinx/bin/activate ] || python3 -m venv py-sphinx --system-site-packages
. py-sphinx/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
