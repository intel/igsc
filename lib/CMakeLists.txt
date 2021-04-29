# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2020 Intel Corporation
cmake_minimum_required(VERSION 3.10)
project(igsc C)
set(LICENSE Apache)

if(WIN32)
    configure_file (
        "${PROJECT_SOURCE_DIR}/igsc_lib.rc.in"
        "${PROJECT_BINARY_DIR}/igsc_lib.rc"
    )
endif()

if(ENABLE_ENUM)
    set(ENUM_SOURCES
        $<$<BOOL:${UNIX}>:enum/igsc_enum_udev.c>
        $<$<BOOL:${WIN32}>:enum/igsc_enum_windows.c>
    )
else()
    set(ENUM_SOURCES enum/igsc_enum_stubs.c)
endif()

set(LIBSOURCES
    igsc_lib.c
    ifr.c
    oprom.c
    oprom_parser.c
    ${ENUM_SOURCES}
    $<$<BOOL:${ENABLE_PERF}>:igsc_perf.c>
    $<$<BOOL:${WIN32}>:${PROJECT_BINARY_DIR}/igsc_lib.rc>
)

add_library(${PROJECT_NAME} SHARED ${LIBSOURCES})
set_target_properties(${PROJECT_NAME}
                      PROPERTIES PUBLIC_HEADER ${CMAKE_SOURCE_DIR}/include/igsc_lib.h)

target_include_directories(${PROJECT_NAME} PRIVATE .)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

target_compile_definitions(
  ${PROJECT_NAME}
  PRIVATE IGSC_DLL_EXPORTS
  PRIVATE $<$<BOOL:${ENABLE_ENUM}>:IGSC_ENUM>
  PRIVATE $<$<BOOL:${SYSLOG}>:SYSLOG>
  PRIVATE $<$<BOOL:${ENABLE_PERF}>:IGSC_PERF>
)
set_target_properties(
  ${PROJECT_NAME} PROPERTIES C_VISIBILITY_PRESET hidden
  VERSION ${GSC_VERSION_STRING} SOVERSION ${GSC_VERSION_MAJOR}
)

if(ENABLE_ENUM)
  if(UNIX)
    find_library(UDEV_LIB udev REQUIRED)
    find_path(UDEV_INCLUDE_DIR libudev.h REQUIRED)
    target_include_directories(${PROJECT_NAME} PRIVATE ${UDEV_INCLUDE_DIR})
  endif()
  target_link_libraries(${PROJECT_NAME} $<$<BOOL:${UNIX}>:${UDEV_LIB}>)
endif()

target_link_libraries(${PROJECT_NAME}
                      LIBMETEE $<$<BOOL:${WIN32}>:CfgMgr32.lib>)

install(
  TARGETS ${PROJECT_NAME}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  PUBLIC_HEADER DESTINATION include
)
