# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2020-2024 Intel Corporation

find_package(Doxygen REQUIRED)

get_target_property(IGSC_PUBLIC_HEADER igsc PUBLIC_HEADER)

set(DOXYGEN_INPUT ${IGSC_PUBLIC_HEADER})
set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/doxygen)
set(DOXYGEN_INDEX_FILE ${DOXYGEN_OUTPUT_DIR}/html/index.html)
set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/doxyfile.in)
set(DOXYFILE_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)

file(MAKE_DIRECTORY ${DOXYGEN_OUTPUT_DIR})
add_custom_command(OUTPUT ${DOXYGEN_INDEX_FILE}
                   DEPENDS ${IGSC_PUBLIC_HEADER}
		   COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
                   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		   MAIN_DEPENDENCY ${DOXYFILE_IN}
                   COMMENT "Generating docs")

add_custom_target(Doxygen DEPENDS ${DOXYGEN_INDEX_FILE})
add_dependencies(igsc Doxygen)
if(UNIX)
  install(DIRECTORY ${DOXYGEN_OUTPUT_DIR}/man/man3
          DESTINATION ${CMAKE_INSTALL_MANDIR}
  )
  install(DIRECTORY ${DOXYGEN_OUTPUT_DIR}/html
          DESTINATION ${CMAKE_INSTALL_DOCDIR}
  )
else()
  install(DIRECTORY ${DOXYGEN_OUTPUT_DIR}/html DESTINATION doc)
endif()

find_package(Sphinx REQUIRED)

set(SPHINX_SOURCE ${CMAKE_CURRENT_SOURCE_DIR})
set(SPHINX_BUILD ${CMAKE_CURRENT_BINARY_DIR}/sphinx)
set(SPHINX_INDEX_FILE ${SPHINX_BUILD}/index.html)
file(GLOB_RECURSE RST_FILES ${CMAKE_SOURCE_DIR}/*.rst)

add_custom_command(OUTPUT ${SPHINX_INDEX_FILE}
                   COMMAND ${SPHINX_EXECUTABLE} -b html
                   -Dbreathe_projects.igsc=${DOXYGEN_OUTPUT_DIR}/xml
                   ${SPHINX_SOURCE} ${SPHINX_BUILD}
                   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                   DEPENDS ${RST_FILES} ${DOXYGEN_INDEX_FILE}
                   MAIN_DEPENDENCY ${SPHINX_SOURCE}/conf.py
                   COMMENT "Generating documentation with Sphinx")

add_custom_target(Sphinx DEPENDS ${SPHINX_INDEX_FILE})
