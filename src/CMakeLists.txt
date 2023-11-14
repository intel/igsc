# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2022 Intel Corporation
cmake_minimum_required(VERSION 3.10)
project(igsc-cli C)
set(LICENSE Apache)

if(WIN32)
    configure_file (
        "${PROJECT_SOURCE_DIR}/igsc_cli.rc.in"
        "${PROJECT_BINARY_DIR}/igsc_cli.rc"
    )
endif()

set(SOURCES
    igsc_cli.c
    $<$<BOOL:${WIN32}>:${PROJECT_BINARY_DIR}/igsc_cli.rc>
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

target_link_libraries(${PROJECT_NAME} igsc)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME igsc)


if(ENABLE_TEST_GENERIC_GFSP_API)
  target_compile_definitions(${PROJECT_NAME} PRIVATE -DENABLE_TEST_GENERIC_GFSP_API)
endif()

if(NOT BUILD_SHARED_LIBS)
  if(CMAKE_C_COMPILER_ID MATCHES Clang OR
     CMAKE_C_COMPILER_ID MATCHES AppleClang OR
     CMAKE_C_COMPILER_ID MATCHES GNU)
    target_link_options(${PROJECT_NAME} PRIVATE -static-libgcc -static)
  endif()
endif()

install(
  TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
