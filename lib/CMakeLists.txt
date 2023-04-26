# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2022 Intel Corporation
cmake_minimum_required(VERSION 3.10)
project(igsc C)
set(LICENSE Apache)

if(WIN32)
    configure_file (
        "${PROJECT_SOURCE_DIR}/igsc_lib.rc.in"
        "${PROJECT_BINARY_DIR}/igsc_lib.rc"
    )
endif()

set(ENUM_SOURCES
     $<$<BOOL:${UNIX}>:enum/igsc_enum_udev.c>
     $<$<BOOL:${WIN32}>:enum/igsc_enum_windows.c>
)

set(POWER_SOURCES
    $<$<BOOL:${UNIX}>:power/igsc_power_udev.c>
    $<$<BOOL:${WIN32}>:power/igsc_power_windows.c>
)

set(LIBSOURCES
    igsc_lib.c
    igsc_log.c
    ifr.c
    oprom.c
    oprom_parser.c
    fw_data_parser.c
    ${ENUM_SOURCES}
    ${POWER_SOURCES}
    $<$<BOOL:${ENABLE_PERF}>:igsc_perf.c>
    $<$<BOOL:${WIN32}>:${PROJECT_BINARY_DIR}/igsc_lib.rc>
)

add_library(${PROJECT_NAME} ${LIBSOURCES})
set_target_properties(${PROJECT_NAME}
                      PROPERTIES PUBLIC_HEADER ${CMAKE_SOURCE_DIR}/include/igsc_lib.h)

target_include_directories(${PROJECT_NAME} PRIVATE .)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

target_compile_definitions(
  ${PROJECT_NAME}
  PRIVATE $<$<BOOL:${BUILD_SHARED_LIBS}>:IGSC_DLL_EXPORTS>
  PRIVATE $<$<BOOL:${BUILD_SHARED_LIBS}>:IGSC_DLL>
  PRIVATE $<$<BOOL:${SYSLOG}>:SYSLOG>
  PRIVATE $<$<BOOL:${ENABLE_PERF}>:IGSC_PERF>
)
set_target_properties(
  ${PROJECT_NAME} PROPERTIES C_VISIBILITY_PRESET hidden
  VERSION ${GSC_VERSION_STRING} SOVERSION ${GSC_VERSION_MAJOR}
)

if(UNIX)
  find_library(UDEV_LIB udev REQUIRED)
  find_path(UDEV_INCLUDE_DIR libudev.h REQUIRED)
  target_include_directories(${PROJECT_NAME} PRIVATE ${UDEV_INCLUDE_DIR})
endif()

target_link_libraries(${PROJECT_NAME}
                      metee::metee $<$<BOOL:${WIN32}>:CfgMgr32.lib> $<$<BOOL:${UNIX}>:${UDEV_LIB}>)

install(
  TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}Targets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  PUBLIC_HEADER DESTINATION include
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
  VERSION ${GSC_VERSION_STRING}
  COMPATIBILITY AnyNewerVersion
)

export(EXPORT ${PROJECT_NAME}Targets
  FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}Targets.cmake"
  NAMESPACE ${PROJECT_NAME}::
)
configure_file(cmake/${PROJECT_NAME}Config.cmake
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}Config.cmake"
  COPYONLY
)
set(ConfigPackageLocation lib/cmake/${PROJECT_NAME})
install(EXPORT ${PROJECT_NAME}Targets
  FILE ${PROJECT_NAME}Targets.cmake
  NAMESPACE ${PROJECT_NAME}::
  DESTINATION ${ConfigPackageLocation}
)

install(FILES cmake/${PROJECT_NAME}Config.cmake
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}ConfigVersion.cmake"
  DESTINATION ${ConfigPackageLocation}
)
