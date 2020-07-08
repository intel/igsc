# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2020 Intel Corporation

find_package(CMocka CONFIG REQUIRED)
include(AddCMockaTest)
enable_testing()

get_target_property(IGCS_INCLUDE_DIRS igsc INCLUDE_DIRECTORIES)

add_cmocka_test(igsc_tests
                SOURCES igsc_tests.c ../lib/igsc_lib.c ../lib/igsc_oprom.c
                LINK_LIBRARIES cmocka LIBMETEE
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS}
                LINK_OPTIONS  "-Wl,--wrap=_test_calloc -Wl,--wrap=_test_malloc")
add_cmocka_test_environment(igsc_tests)

add_cmocka_test(firmware_parser_tests
                SOURCES firmware_parser_tests.c ../lib/igsc_oprom.c
                LINK_LIBRARIES cmocka LIBMETEE
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS}
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -g -DUNIT_TESTING=1)
add_cmocka_test_environment(firmware_parser_tests)

add_cmocka_test(oprom_tests
                SOURCES oprom_tests.c
                LINK_LIBRARIES cmocka LIBMETEE
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS}
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1)
add_cmocka_test_environment(oprom_tests)

add_cmocka_test(version_tests
                SOURCES version_tests.c tee_mock.c ../lib/igsc_oprom.c
                LINK_LIBRARIES cmocka LIBMETEE
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS}
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1)
add_cmocka_test_environment(version_tests)

add_cmocka_test(oprom_parser_tests
                SOURCES oprom_parser_tests.c
                LINK_LIBRARIES cmocka LIBMETEE
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS}
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1)
add_cmocka_test_environment(oprom_parser_tests)

add_cmocka_test(cli_tests
                SOURCES cli_tests.c enum_mock.c ../lib/igsc_lib.c ../lib/igsc_oprom.c
                LINK_LIBRARIES cmocka LIBMETEE
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS} ../src
                LINK_OPTIONS  "-Wl,--wrap=igsc_device_iterator_next -Wl,--wrap=igsc_device_iterator_create -Wl,--wrap=igsc_device_iterator_destroy")
add_cmocka_test_environment(cli_tests)
