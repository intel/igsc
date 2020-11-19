# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2020 Intel Corporation
cmake_minimum_required(VERSION 3.10)

# Find install metee library
find_library(
  LIBMETEE_LIB
  NAMES metee
  PATHS ENV METEE_LIB_PATH)
find_path(
  LIBMETEE_HEADER
  NAMES metee.h
  PATHS ENV METEE_HEADER_PATH)

# In case there is no METEE install get it from git
if(${LIBMETEE_LIB} MATCHES "LIBMETEE_LIB-NOTFOUND"
   OR ${LIBMETEE_HEADER} MATCHES "LIBMETEE_HEADER-NOTFOUND")
  # Download and unpack metee at configure time
  if(DEFINED ENV{LIBMETEE_REPO})
    set(LIBMETEE_REPO $ENV{LIBMETEE_REPO})
  endif()
  if(NOT LIBMETEE_REPO)
    set(LIBMETEE_REPO "https://github.com/intel/metee.git")
  endif()
  # If the repo is local repository convert it cmake path
  if(IS_DIRECTORY ${LIBMETEE_REPO})
    file(TO_CMAKE_PATH ${LIBMETEE_REPO} LIBMETEE_REPO)
  endif()
  message("LIBMETEE_REPO ${LIBMETEE_REPO}")
  if(DEFINED ENV{LIBMETEE_TAG})
    set(LIBMETEE_TAG $ENV{LIBMETEE_TAG})
  endif()
  if(NOT LIBMETEE_TAG)
    set(LIBMETEE_TAG "master")
  endif()
  message("LIBMETEE_TAG ${LIBMETEE_TAG}")
  configure_file(metee-down.cmake.in metee-download/CMakeLists.txt)
  execute_process(
    COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/metee-download)
  if(result)
    message(FATAL_ERROR "CMake step for metee failed: ${result}")
  endif(result)
  execute_process(
    COMMAND ${CMAKE_COMMAND} --build .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/metee-download)
  if(result)
    message(FATAL_ERROR "Build step for metee failed: ${result}")
  endif(result)

  # Add METEE external project
  set(LIBMETEE_PATH ${CMAKE_CURRENT_BINARY_DIR}/metee)
  set(LIBMETEE_LIB_BASENAME
      ${CMAKE_STATIC_LIBRARY_PREFIX}metee${CMAKE_STATIC_LIBRARY_SUFFIX})
  set(LIBMETEE_LIB
      ${LIBMETEE_PATH}/${CMAKE_CFG_INTDIR}/${LIBMETEE_LIB_BASENAME})
  set(LIBMETEE_HEADER ${LIBMETEE_PATH}/include)
  include(ExternalProject)
  ExternalProject_Add(
    libmetee
    SOURCE_DIR ${LIBMETEE_PATH}
    BUILD_BYPRODUCTS ${LIBMETEE_LIB}
    BUILD_IN_SOURCE YES
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    TEST_COMMAND ""
    INSTALL_COMMAND ""
    CMAKE_ARGS -DBUILD_MSVC_RUNTIME_STATIC=ON)
endif()

# Import METEE library to the project
add_library(LIBMETEE STATIC IMPORTED)
set_target_properties(
  LIBMETEE
  PROPERTIES IMPORTED_LOCATION ${LIBMETEE_LIB} IMPORTED_IMPLIB ${LIBMETEE_LIB}
             INTERFACE_INCLUDE_DIRECTORIES ${LIBMETEE_HEADER})
add_dependencies(LIBMETEE libmetee)
