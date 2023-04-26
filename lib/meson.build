# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2020 Intel Corporation

if get_option('syslog')
  add_project_arguments('-DSYSLOG', language : 'c')
endif

srcs = [
  'igsc_lib.c',
  'igsc_log.c',
  'ifr.c',
  'oprom.c',
  'oprom_parser.c',
  'fw_data_parser.c',
  'enum/igsc_enum_udev.c',
  'power/igsc_power_udev.c',
]

libudev_dep = dependency('libudev')
deps = [libudev_dep]

if get_option('enable_perf')
  add_project_arguments('-DIGSC_PERF', language : 'c')
  srcs += ['igsc_perf.c']
endif
cargs = []
metee_proj = subproject('metee', required: true)
metee_dep = metee_proj.get_variable('metee_dep_static')

deps += [metee_dep]

igsc_shared = shared_library(
  'igsc',
  sources : [
    srcs,
  ],
  soversion : lt_major,
  version : ver_str,
  include_directories : inc_dirs,
  dependencies : [
    deps,
  ],
  c_args : [
    cargs,
  ],
  install : true,
)

igsc_static = static_library(
  'igsc',
  objects: igsc_shared.extract_all_objects(),
  include_directories : inc_dirs,
  dependencies : [
    deps,
  ],
  c_args : [
    cargs,
  ],
  install : true
)

igsc_dep = declare_dependency(
  link_with : igsc_shared,
  include_directories : inc_dirs,
  dependencies : deps
)

igsc_dep_static = declare_dependency(
  link_with : igsc_static,
  include_directories : inc_dirs,
  dependencies : deps
)
