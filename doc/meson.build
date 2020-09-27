# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2020 Intel Corporation
doxygen = find_program('doxygen', required: false)
if doxygen.found()
  conf_data = configuration_data()
  conf_data.set('DOXYGEN_INPUT_DIRECTORY', meson.source_root())
  conf_data.set('DOXYGEN_OUTPUT_DIRECTORY', meson.current_build_dir())

  doxyfile = configure_file(
    input: 'doxyfile.in',
    output: 'Doxyfile',
    configuration: conf_data
  )

  custom_target('doc',
    build_by_default: false,
    command: [doxygen, doxyfile],
    output: ['html']
  )
endif
