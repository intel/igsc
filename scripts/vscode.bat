REM SPDX-License-Identifier: Apache-2.0
REM Copyright (C) 2020-2021 Intel Corporation

@echo off

set path=%path%;%CMAKE_PATH%

set VS_CODE="Visual Studio 16 2019"
set CMAKE_ARGS="-DLIBMETEE_REPO=https://github.com/intel/metee
cmake %CMAKE_ARGS% -G %VS_CODE% -S . -B build
cmake --build build --config Release -t package
FOR %%F in (build\igsc-*-win64.zip) DO set pkgversioned=%%F
copy /b /y /v %pkgversioned% build\igsc-win64.zip
