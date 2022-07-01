# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2021-2022 Intel Corporation
find_path(METEE_INCLUDE_DIR
          NAMES metee.h
          PATHS /usr/include ENV METEE_HEADER_PATH
)

find_library(METEE_LIBRARY metee 
             PATHS ENV METEE_LIB_PATH
)

set(METEE_INCLUDE_DIRS ${METEE_INCLUDE_DIR})
set(METEE_LIBRARIES ${METEE_LIBRARY})

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(metee FOUND_VAR METEE_FOUND
                                  REQUIRED_VARS METEE_LIBRARY METEE_INCLUDE_DIR)

mark_as_advanced(METEE_INCLUDE_DIR METEE_LIBRARY)

if(METEE_FOUND AND NOT TARGET metee::metee)
  add_library(metee::metee UNKNOWN IMPORTED)
  set_target_properties(metee::metee PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${METEE_INCLUDE_DIR}")
  set_property(TARGET metee::metee APPEND PROPERTY IMPORTED_LOCATION "${METEE_LIBRARY}")
endif()
