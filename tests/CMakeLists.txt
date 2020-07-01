# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2019-2020 Intel Corporation

find_package(CMocka CONFIG REQUIRED)
include(AddCMockaTest)
enable_testing()

get_target_property(IGCS_INCLUDE_DIRS igsc INCLUDE_DIRECTORIES)

add_cmocka_test(igsc_tests
                SOURCES igsc_tests.c ../lib/igsc_lib.c ../lib/igsc_oprom.c
                LINK_LIBRARIES cmocka
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1
                LINK_OPTIONS  "-Wl,--wrap=_test_calloc -Wl,--wrap=_test_malloc")
target_link_libraries(igsc_tests PRIVATE LIBMETEE)
target_include_directories(igsc_tests
                           PRIVATE ${IGCS_INCLUDE_DIRS})
add_cmocka_test_environment(igsc_tests)

add_cmocka_test(firmware_parser_tests
                SOURCES firmware_parser_tests.c
                LINK_LIBRARIES cmocka
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -g -DUNIT_TESTING=1)
target_link_libraries(firmware_parser_tests PRIVATE LIBMETEE)
target_include_directories(firmware_parser_tests
                            PRIVATE ${IGCS_INCLUDE_DIRS})
add_cmocka_test_environment(firmware_parser_tests)

add_cmocka_test(oprom_tests
                SOURCES oprom_tests.c
                LINK_LIBRARIES cmocka
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1)
target_link_libraries(oprom_tests PRIVATE LIBMETEE)
target_include_directories(oprom_tests
                           PRIVATE ${IGCS_INCLUDE_DIRS})
add_cmocka_test_environment(oprom_tests)

add_cmocka_test(version_tests
                SOURCES version_tests.c tee_mock.c
                LINK_LIBRARIES cmocka
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1)
target_link_libraries(version_tests PRIVATE LIBMETEE)
target_include_directories(version_tests
                            PRIVATE ${IGCS_INCLUDE_DIRS})
add_cmocka_test_environment(version_tests)

add_cmocka_test(oprom_parser_tests
                SOURCES oprom_parser_tests.c
                LINK_LIBRARIES cmocka
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1)
target_link_libraries(oprom_parser_tests PRIVATE LIBMETEE)
target_include_directories(oprom_parser_tests
                           PRIVATE ${IGCS_INCLUDE_DIRS})
add_cmocka_test_environment(oprom_parser_tests)

add_cmocka_test(cli_tests
                SOURCES cli_tests.c enum_mock.c ../lib/igsc_lib.c ../lib/igsc_oprom.c
                LINK_LIBRARIES cmocka
                COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS} -DUNIT_TESTING=1
                LINK_OPTIONS  "-Wl,--wrap=igsc_device_iterator_next -Wl,--wrap=igsc_device_iterator_create -Wl,--wrap=igsc_device_iterator_destroy")
target_link_libraries(cli_tests PRIVATE LIBMETEE)
target_include_directories(cli_tests
                           PRIVATE ${IGCS_INCLUDE_DIRS}
                           PRIVATE ../src)
add_cmocka_test_environment(cli_tests)
