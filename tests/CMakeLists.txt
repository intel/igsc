# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2020 Intel Corporation

find_package(CMocka CONFIG REQUIRED)
include(AddCMockaTest)
enable_testing()

message("cmocka include ${CMOCKA_INCLUDE_DIR}")
message("cmocka lib  ${CMOCKA_LIBRARIES}")

get_target_property(IGCS_INCLUDE_DIRS igsc INCLUDE_DIRECTORIES)

add_cmocka_test(igsc_tests
                SOURCES ../lib/igsc_lib.c ../lib/oprom.c igsc_tests.c
                LINK_LIBRARIES ${CMOCKA_LIBRARIES} LIBMETEE
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -Digsc_strdup=test_strdup -DUNIT_TESTING=1
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS} ${CMOCKA_INCLUDE_DIR}
                LINK_OPTIONS  "-Wl,--wrap=_test_calloc -Wl,--wrap=image_oprom_parse")
add_cmocka_test_environment(igsc_tests)

add_cmocka_test(firmware_parser_tests
                SOURCES firmware_parser_tests.c ../lib/oprom.c ../lib/oprom_parser.c
                LINK_LIBRARIES ${CMOCKA_LIBRARIES} LIBMETEE
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS} ${CMOCKA_INCLUDE_DIR}
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -g -DUNIT_TESTING=1)
add_cmocka_test_environment(firmware_parser_tests)

add_cmocka_test(version_tests
                SOURCES version_tests.c tee_mock.c ../lib/oprom.c ../lib/oprom_parser.c
                LINK_LIBRARIES ${CMOCKA_LIBRARIES} LIBMETEE
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS} ${CMOCKA_INCLUDE_DIR}
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -Digsc_strdup=test_strdup -DUNIT_TESTING=1)
add_cmocka_test_environment(version_tests)

add_cmocka_test(oprom_tests
                SOURCES oprom_tests.c ../lib/oprom.c ../lib/oprom_parser.c
                LINK_LIBRARIES ${CMOCKA_LIBRARIES} LIBMETEE
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS} ${CMOCKA_INCLUDE_DIR}
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1
                LINK_OPTIONS  "-Wl,--wrap=image_oprom_parse -Wl,--wrap=image_oprom_get_type")
add_cmocka_test_environment(oprom_tests)

add_cmocka_test(oprom_parser_tests
                SOURCES oprom_parser_tests.c
                LINK_LIBRARIES ${CMOCKA_LIBRARIES} LIBMETEE
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS} ${CMOCKA_INCLUDE_DIR}
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1)
add_cmocka_test_environment(oprom_parser_tests)

add_cmocka_test(cli_tests
                SOURCES cli_tests.c ../lib/igsc_lib.c ../lib/oprom.c ../lib/oprom_parser.c enum_mock.c
                LINK_LIBRARIES ${CMOCKA_LIBRARIES} LIBMETEE
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -Dmain=ut_main -Digsc_strdup=test_strdup -DUNIT_TESTING=1
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS} ${CMOCKA_INCLUDE_DIR} ../src
                LINK_OPTIONS  "-Wl,--wrap=igsc_device_iterator_next -Wl,--wrap=igsc_device_iterator_create -Wl,--wrap=igsc_device_iterator_destroy")
add_cmocka_test_environment(cli_tests)

add_cmocka_test(igsc_enum_tests
                SOURCES igsc_enum_tests.c
                LINK_LIBRARIES ${CMOCKA_LIBRARIES} LIBMETEE udev
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1
                INCLUDE_DIRECTORIES ${IGCS_INCLUDE_DIRS} ${CMOCKA_INCLUDE_DIR})
add_cmocka_test_environment(igsc_enum_tests)
