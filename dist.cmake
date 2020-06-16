# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2020 Intel Corporation

# Source package
set(ARCHIVE_NAME ${PROJECT_NAME}-${GSC_VERSION_STRING})
add_custom_target(dist
    COMMAND git archive --prefix=${ARCHIVE_NAME}/ HEAD
        | bzip2 > ${CMAKE_BINARY_DIR}/${ARCHIVE_NAME}.tar.bz2
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Create the source package"
)
