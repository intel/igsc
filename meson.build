# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2020 Intel Corporation
project('igsc', 'c',
  version : run_command('scripts/get-version.py').stdout().strip(),
  license : 'Apache 2.0',
  default_options : ['warning_level=2', 'c_std=gnu99', 'optimization=2'],
)

# versioning
ver_str = meson.project_version()
ver_list = ver_str.split('.')
lt_major = ver_list[0]
lt_minor = ver_list[1]
lt_patch = ver_list[2].split('-')[0]

add_project_arguments('-DIGSC_VERSION="' + ver_str + '"', language : 'c')

# hide/enable some warnings
warning_flags = [
  '-Wno-unused-command-line-argument',
  '-Wsign-compare',
  '-Wconversion',
  '-Woverflow',
  '-Wstack-protector',
  '-Winit-self',
  '-Wstrict-prototypes',
]

# secure compile flags
security_flags = [
  '-fstack-protector-strong',
  '-Wformat',
  '-Wformat-security',
  '-fno-strict-overflow',
  '-fno-delete-null-pointer-checks',
  '-fwrapv'
]

if get_option('optimization').to_int() >= 2
  security_flags += [
    '-D_FORTIFY_SOURCE=2'
  ]
endif

debug_flags = []
if get_option('buildtype') == 'debug'
  debug_flags += [
    '-O0',
    '-g3',
    '-ggdb'
  ]
endif

cc = meson.get_compiler('c')
add_project_arguments(cc.get_supported_arguments(warning_flags), language : 'c')
add_project_arguments(cc.get_supported_arguments(security_flags), language : 'c')
add_project_arguments(cc.get_supported_arguments(debug_flags), language : 'c')
add_project_arguments('-D_XOPEN_SOURCE=700', language : 'c')
add_project_arguments('-D_GNU_SOURCE', language : 'c')

# FIXME: until https://github.com/mesonbuild/meson/issues/1140 is fixed
global_link_args = []
test_link_args = [
  '-Wl,-z,relro',
  '-Wl,-z,now',
  '-Wl,-z,noexecstack',
]
foreach link_arg: test_link_args
  if cc.has_link_argument(link_arg)
    global_link_args += link_arg
  endif
endforeach
add_project_link_arguments(
  global_link_args,
  language: 'c'
)

inc_dirs = include_directories('include')

subdir('lib')

if get_option('enable_cli')
  subdir('src')
endif

subdir('doc')
