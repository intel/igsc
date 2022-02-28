# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2022 Intel Corporation
cmake_minimum_required(VERSION 3.10)
project(igsc C)
set(LICENSE Apache)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")

include(version.cmake)
add_definitions(-DIGSC_VERSION=\"${GSC_VERSION_STRING}\")
include(GNUInstallDirs)
include(metee.cmake)

if(NOT WIN32)
    option(SYSLOG "Use syslog for logging" ON)
endif()
option(ENABLE_PERF "Enable performance counters" OFF)
option(ENABLE_DOCS "Enable docs build" OFF)
option(ENABLE_TESTS "Perform unit tests after build" OFF)
option(ENABLE_WERROR "Enable treat warnings as error" ON)
option(ENABLE_CLI "Enable command line tool build" ON)
option(ENABLE_CLI_FORCE "Enable command line tool build also if enumeration is not supported" OFF)
option(ENABLE_ENUM "Enable enumeration build" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)

include(CMakeDependentOption)
cmake_dependent_option(CLI_ENABLED "Enable command line tool build" ON "ENABLE_ENUM;ENABLE_CLI" OFF)
cmake_dependent_option(TESTS_ENABLED "Perform unit tests after build" ON "ENABLE_ENUM;ENABLE_CLI;ENABLE_TESTS" OFF)

set(COMPILE_OPTIONS_NX
    -Wall
    -Wextra
    -Wsign-compare
    -Wformat-security
    -Wstack-protector
    -Winit-self
    -Wstrict-prototypes
    -Wconversion
    -Woverflow
    -fwrapv
    -fPIC
    -fstack-protector-strong
    "$<$<CONFIG:Debug>:-DDEBUG;-D_DEBUG>"
    "$<$<CONFIG:Debug>:-O0;-g3;-ggdb>"
    "$<$<CONFIG:Release>:-O2;-D_FORTIFY_SOURCE=2>"
    "$<$<BOOL:${ENABLE_WERROR}>:-Werror>"
)

set(COMPILE_OPTIONS_GCC
    -fno-strict-overflow
    -fno-delete-null-pointer-checks
)

set(COMPILE_OPTIONS_WIN
    /DUNICODE
    /D_UNICODE
    /W4
    /MT$<$<CONFIG:Debug>:d>
    /GS
    /sdl
    "$<$<BOOL:${ENABLE_WERROR}>:/WX>"
)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(LINK_OPTIONS_NX "-z noexecstack -z relro -z now")
set(LINK_EXE_OPTIONS_NX "-pie")
set(LINK_OPTIONS_WIN "/NXCompat /DynamicBase /GUARD:CF")

if(CMAKE_C_COMPILER_ID MATCHES Clang OR
   CMAKE_C_COMPILER_ID MATCHES AppleClang)
    set(COMPILE_OPTIONS ${COMPILE_OPTIONS_NX})
    set(LINK_OPTIONS ${LINK_OPTIONS_NX})
    set(LINX_EXE_OPTIONS ${LINK_EXE_OPTIONS_NX})
elseif(CMAKE_C_COMPILER_ID MATCHES GNU)
    set(COMPILE_OPTIONS ${COMPILE_OPTIONS_NX} ${COMPILE_OPTIONS_GCC})
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

if(CLI_ENABLED OR ENABLE_CLI_FORCE)
  add_subdirectory("src")
endif()

if(TESTS_ENABLED)
  add_subdirectory("tests")
endif()

if(ENABLE_DOCS)
  add_subdirectory("doc")
endif()

include(dist.cmake)

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
if(WIN32 AND NOT UNIX)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()
set(CPACK_PACKAGE_VERSION_MAJOR ${GSC_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${GSC_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${GSC_VERSION_PATCH})
set(CPACK_PACKAGE_VENDOR "Intel, Inc")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Graphics System Controller Firmware Update Library")
set(CPACK_PACKAGE_DESCRIPTION_FILE ${PROJECT_SOURCE_DIR}/README.md)
include(CPack)
