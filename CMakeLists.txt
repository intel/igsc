# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2020 Intel Corporation
cmake_minimum_required(VERSION 3.10)
project(igsc C)
set(LICENSE Apache)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")

include(version.cmake)
include(GNUInstallDirs)
include(metee.cmake)

if(NOT WIN32)
    option(SYSLOG "Use syslog for logging" ON)
endif()
option(ENABLE_PERF "Enable performance counters" OFF)
option(BUILD_DOCS "Enable docs build" OFF)
option(ENABLE_TESTS "Perform unit tests after build" OFF)

set(COMPILE_OPTIONS_NX
    -Wno-unused-parameter
    -Wall
    -Wextra
    -Wsign-compare
    -Wformat-security
    -Wstack-protector
    -Winit-self
    -fPIC
    "$<$<CONFIG:DEBUG>:-O0;-g3;-ggdb>"
)

set(COMPILE_OPTIONS_WIN
    /DUNICODE
    /D_UNICODE
    /W4
    /MT$<$<CONFIG:Debug>:d>
    /GS
    /sdl
)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(LINK_OPTIONS_NX "-z noexecstack -z relro -z now")
set(LINK_EXE_OPTIONS_NX "-pie")
set(LINK_OPTIONS_WIN "/NXCompat /DynamicBase /GUARD:CF")

if(CMAKE_C_COMPILER_ID MATCHES Clang OR
   CMAKE_C_COMPILER_ID MATCHES AppleClang OR
   CMAKE_C_COMPILER_ID MATCHES GNU)
    set(COMPILE_OPTIONS ${COMPILE_OPTIONS_NX})
    set(LINK_OPTIONS ${LINK_OPTIONS_NX})
    set(LINX_EXE_OPTIONS ${LINK_EXE_OPTIONS_NX})
elseif(CMAKE_C_COMPILER_ID MATCHES MSVC)
    set(COMPILE_OPTIONS ${COMPILE_OPTIONS_WIN})
    set(LINK_OPTIONS ${LINK_OPTIONS_WIN})
endif()

set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} ${LINK_OPTIONS} ${LINX_EXE_OPTIONS}")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINK_OPTIONS}")

add_subdirectory("lib")
add_subdirectory("src")

if(BUILD_DOCS)
  add_subdirectory("doc")
endif()

include(dist.cmake)

if(ENABLE_TESTS)
  add_subdirectory("tests")
endif()
