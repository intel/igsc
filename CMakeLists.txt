# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2023 Intel Corporation
cmake_minimum_required(VERSION 3.10)
project(igsc C)
set(LICENSE Apache)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_BINARY_DIR}")
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")

include(version.cmake)
add_definitions(-DIGSC_VERSION=\"${GSC_VERSION_STRING}\")
include(GNUInstallDirs)

if(NOT WIN32)
    option(SYSLOG "Use syslog for logging" ON)
endif()
option(ENABLE_PERF "Enable performance counters" OFF)
option(ENABLE_DOCS "Enable docs build" OFF)
option(ENABLE_TESTS "Perform unit tests after build" OFF)
option(ENABLE_WERROR "Enable treat warnings as error" ON)
option(ENABLE_CLI "Enable command line tool build" ON)
option(ENABLE_TEST_GENERIC_GFSP_API "Enable test generic GFSP API" ON)
option(BUILD_SHARED_LIBS "Build shared library" ON)
option (BUILD_USE_CONAN "Use Conan for dependencies download" NO)

include(CMakeDependentOption)
cmake_dependent_option(TESTS_ENABLED "Perform unit tests after build" ON "ENABLE_CLI;ENABLE_TESTS" OFF)

if(BUILD_USE_CONAN)
  include(conan)
  conan_cmake_autodetect(settings)
  # conan.cmake failed to detect MT, force-replace it
  string(REPLACE "compiler.runtime=MD" "compiler.runtime=MT" flags "${settings}")
  conan_cmake_install(PATH_OR_REFERENCE ${CMAKE_CURRENT_SOURCE_DIR} SETTINGS ${flags})
endif()
message(${CMAKE_MODULE_PATH})
include(metee.cmake)

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
    "$<$<CONFIG:Release>:/Zi>"
)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(LINK_OPTIONS_NX "-z noexecstack -z relro -z now")
set(LINK_EXE_OPTIONS_NX "-pie")
set(LINK_OPTIONS_WIN "/NXCompat /DynamicBase /GUARD:CF /INCREMENTAL:NO /DEBUG:FULL /OPT:REF /OPT:ICF")

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

if(ENABLE_CLI)
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
