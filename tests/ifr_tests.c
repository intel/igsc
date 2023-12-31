/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2022 Intel Corporation
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <cmocka.h>

char *test_strdup(const char *str)
{
    char *new_str = malloc(strlen(str) + 1);
    if (new_str)
    {
        strcpy(new_str, str);
    }

    return new_str;
}

#include "igsc_lib.h"
#include "dev_info_mock.c"
#include "../src/igsc_cli.c"

static void test_arg_free(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        free(argv[i]);
    }
}

static int group_setup(void **state)
{
    char **argv;

    argv = calloc(10, sizeof (char *));
    if (argv == NULL)
    {
        return -1;
    }

    argv[0] = test_strdup("igsc");

    *state = argv;

    return 0;
}

static int group_teardown(void **state)
{
    char **argv = *state;
    free(argv[0]);
    free(argv);
    *state = NULL;
    return 0;
}

/**
 * test: igsc ifr get-status
 */
static void test_ifr_get_status_good(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("get-status");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc ifr get-status blah blah blah blah
 */
static void test_ifr_get_status_bad(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("get-status");
    argv[argc++] = test_strdup("blah");
    argv[argc++] = test_strdup("blah");
    argv[argc++] = test_strdup("blah");
    argv[argc++] = test_strdup("blah");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr
 */
static void test_ifr_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr blah
 */
static void test_ifr_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("blah");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test scan --tile 0
 */
static void test_ifr_run_test_good1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("scan");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test scan --tile 1
 */
static void test_ifr_run_test_good2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("scan");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("1");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --tile all
 */
static void test_ifr_run_test_good3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("all");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test scan --tile 1
 */
static void test_ifr_run_test_good4(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("scan");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("1");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --tile 0
 */
static void test_ifr_run_test_good5(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test
 */
static void test_ifr_run_test_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test array
 */
static void test_ifr_run_test_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("array");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test array --tile 1 blah
 */
static void test_ifr_run_test_bad3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("array");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("1");
    argv[argc++] = test_strdup("blah");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test bad --tile 1
 */
static void test_ifr_run_test_bad4(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("bad");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("1");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test array --tile 2
 */
static void test_ifr_run_test_bad5(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("1");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("2");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test array --tile 2
 */
static void test_ifr_run_test_bad6(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("array");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("2");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --test array --time 0
 */
static void test_ifr_run_test_bad7(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--test");
    argv[argc++] = test_strdup("array");
    argv[argc++] = test_strdup("--time");
    argv[argc++] = test_strdup("0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-test --temp array --tile 1
 */
static void test_ifr_run_test_bad8(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-test");
    argv[argc++] = test_strdup("--temp");
    argv[argc++] = test_strdup("array");
    argv[argc++] = test_strdup("--tile");
    argv[argc++] = test_strdup("1");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc gfsp get-mem
 */
static void test_gfsp_get_mem_err_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("get-mem");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc gfsp get-mem-err --device
 */
static void test_gfsp_get_mem_err_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("get-mem-err");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc get-mem-ppr-stat
 */
static void test_gfsp_get_mem_ppr_status_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("get-mem-ppr-stat");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc gfsp get-mem-ppr-status --device
 */
static void test_gfsp_get_mem_ppr_status_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("get-mem-ppsr-status");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-array-scan-test --device
 */
static void test_ifr_array_scan_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-array-scan-test");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-array-scan-tests
 */
static void test_ifr_array_scan_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-array-scan-tests");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-mem-ppr-test --device
 */
static void test_ifr_mem_ppr_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-mem-ppr-test");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr run-mem-ppp-test
 */
static void test_ifr_mem_ppr_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("run-mem-ppp-test");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr get-status-ext --device
 */
static void test_ifr_get_status_ext_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("get-status-ext");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr get-status-ex
 */
static void test_ifr_get_status_ext_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("get-status-ex");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr get-repair-info --device
 */
static void test_ifr_get_repair_info_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("get-repair-info");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr get-repair-info --tile
 */
static void test_ifr_get_repair_info_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("get-repair-info");
    argv[argc++] = test_strdup("--tile");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc ifr count-tiles --device
 */
static void test_ifr_count_tiles_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("ifr");
    argv[argc++] = test_strdup("count-tiles");
    argv[argc++] = test_strdup("--device");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc gfsp set-ecc-config no param
 */
static void test_gfsp_ecc_config_set_no_param(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("set-ecc-config");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc gfsp set-ecc-config bad param
 */
static void test_gfsp_ecc_config_set_bad_param(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("set-ecc-config");
    argv[argc++] = test_strdup("-e");
    argv[argc++] = test_strdup("11");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc gfsp set-ecc-config bad param 2
 */
static void test_gfsp_ecc_config_set_bad_param2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("set-ecc-config");
    argv[argc++] = test_strdup("-e");
    argv[argc++] = test_strdup("blah");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc gfsp set-ecc-config good param
 */
static void test_gfsp_ecc_config_set_good_param(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("set-ecc-config");
    argv[argc++] = test_strdup("-e");
    argv[argc++] = test_strdup("1");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc gfsp get-ecc-config
 */
static void test_gfsp_ecc_config_get_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("gfsp");
    argv[argc++] = test_strdup("get-ecc-config");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --payload pload.bin --type fan-table --flags 0x1 --device /dev/mei0
 */
static void test_late_binding_good1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--payload");
    argv[argc++] = test_strdup("pload.bin");
    argv[argc++] = test_strdup("--type");
    argv[argc++] = test_strdup("fan-table");
    argv[argc++] = test_strdup("--flags");
    argv[argc++] = test_strdup("0x1");
    argv[argc++] = test_strdup("--device");
    argv[argc++] = test_strdup("/dev/mei0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --payload pload.bin --type vr-config --flags 0x0
 */
static void test_late_binding_good2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--payload");
    argv[argc++] = test_strdup("pload.bin");
    argv[argc++] = test_strdup("--type");
    argv[argc++] = test_strdup("vr-config");
    argv[argc++] = test_strdup("--flags");
    argv[argc++] = test_strdup("0x0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret == EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --payload --type vr-config --flags 0x0
 * missing payload file
 */
static void test_late_binding_bad1(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--payload");
    argv[argc++] = test_strdup("--type");
    argv[argc++] = test_strdup("vr-config");
    argv[argc++] = test_strdup("--flags");
    argv[argc++] = test_strdup("0x0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --type vr-config --flags 0x0
 * missing --payload
 */
static void test_late_binding_bad2(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--type");
    argv[argc++] = test_strdup("vr-config");
    argv[argc++] = test_strdup("--flags");
    argv[argc++] = test_strdup("0x0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --payload pload.bin --type --flags 0x0
 * missing --type value
 */
static void test_late_binding_bad3(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--payload");
    argv[argc++] = test_strdup("pload.bin");
    argv[argc++] = test_strdup("--type");
    argv[argc++] = test_strdup("--flags");
    argv[argc++] = test_strdup("0x0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --payload pload.bin --flags 0x0
 * missing --type
 */
static void test_late_binding_bad4(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--payload");
    argv[argc++] = test_strdup("pload.bin");
    argv[argc++] = test_strdup("--flags");
    argv[argc++] = test_strdup("0x0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --payload pload.bin --type vr-config --flags
 * missing --flags value
 */
static void test_late_binding_bad5(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--payload");
    argv[argc++] = test_strdup("pload.bin");
    argv[argc++] = test_strdup("--type");
    argv[argc++] = test_strdup("vr-config");
    argv[argc++] = test_strdup("--flags");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --payload pload.bin --type vr-config
 * missing --flags
 */
static void test_late_binding_bad6(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--payload");
    argv[argc++] = test_strdup("pload.bin");
    argv[argc++] = test_strdup("--type");
    argv[argc++] = test_strdup("vr-config");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

/**
 * test: igsc late-binding --payload pload.bin --type fan-config --flags 0x0
 * bad --type value
 */
static void test_late_binding_bad7(void **state)
{
    int ret;
    char **argv = *state;
    int argc = 1;

    argv[argc++] = test_strdup("late-binding");
    argv[argc++] = test_strdup("--payload");
    argv[argc++] = test_strdup("pload.bin");
    argv[argc++] = test_strdup("--type");
    argv[argc++] = test_strdup("fan-config");
    argv[argc++] = test_strdup("--flags");
    argv[argc++] = test_strdup("0x0");

    ret = ut_main(argc, argv);

    test_arg_free(argc, argv);

    assert_true(ret != EXIT_SUCCESS);
}

#undef main
int main(void)
{
    int status = 0;

    const struct CMUnitTest ifr_tests[] = {
        cmocka_unit_test(test_ifr_bad1),
        cmocka_unit_test(test_ifr_bad2),
        cmocka_unit_test(test_ifr_get_status_bad),
        cmocka_unit_test(test_ifr_get_status_good),
        cmocka_unit_test(test_ifr_run_test_good1),
        cmocka_unit_test(test_ifr_run_test_good2),
        cmocka_unit_test(test_ifr_run_test_good3),
        cmocka_unit_test(test_ifr_run_test_good4),
        cmocka_unit_test(test_ifr_run_test_good5),
        cmocka_unit_test(test_ifr_run_test_bad1),
        cmocka_unit_test(test_ifr_run_test_bad2),
        cmocka_unit_test(test_ifr_run_test_bad3),
        cmocka_unit_test(test_ifr_run_test_bad4),
        cmocka_unit_test(test_ifr_run_test_bad5),
        cmocka_unit_test(test_ifr_run_test_bad6),
        cmocka_unit_test(test_ifr_run_test_bad7),
        cmocka_unit_test(test_ifr_run_test_bad8),
        cmocka_unit_test(test_gfsp_get_mem_err_bad1),
        cmocka_unit_test(test_gfsp_get_mem_err_bad2),
        cmocka_unit_test(test_ifr_mem_ppr_bad1),
        cmocka_unit_test(test_ifr_mem_ppr_bad2),
        cmocka_unit_test(test_ifr_get_status_ext_bad1),
        cmocka_unit_test(test_ifr_get_status_ext_bad2),
        cmocka_unit_test(test_ifr_get_repair_info_bad1),
        cmocka_unit_test(test_ifr_get_repair_info_bad2),
        cmocka_unit_test(test_ifr_count_tiles_bad1),
        cmocka_unit_test(test_gfsp_ecc_config_set_no_param),
        cmocka_unit_test(test_gfsp_ecc_config_set_bad_param),
        cmocka_unit_test(test_gfsp_ecc_config_set_bad_param2),
        cmocka_unit_test(test_gfsp_ecc_config_set_good_param),
        cmocka_unit_test(test_gfsp_ecc_config_get_bad1),
        cmocka_unit_test(test_late_binding_good1),
        cmocka_unit_test(test_late_binding_good2),
        cmocka_unit_test(test_late_binding_bad1),
        cmocka_unit_test(test_late_binding_bad2),
        cmocka_unit_test(test_late_binding_bad3),
        cmocka_unit_test(test_late_binding_bad4),
        cmocka_unit_test(test_late_binding_bad5),
        cmocka_unit_test(test_late_binding_bad6),
        cmocka_unit_test(test_late_binding_bad7),
    };

    status += cmocka_run_group_tests(ifr_tests, group_setup, group_teardown);

    return status;
}
