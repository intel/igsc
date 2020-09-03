#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#include "../lib/igsc_lib.c"
#include "dev_info_mock.c"

static int group_setup(void **state)
{
    *state = malloc(sizeof(struct gsc_fwu_fpt_img));
    if (*state == NULL) {
        return -1;
    }

    return 0;
}

static int group_teardown(void **state)
{
     free(*state);
     return 0;
}

static uint32_t __buffer_len(const struct gsc_fwu_fpt_img *fpt)
{
    return sizeof(fpt->header) +
           fpt->header.num_of_entries * sizeof(fpt->entry[0]);
}

static int test_setup(void **state)
{
    struct gsc_fwu_fpt_img *fpt = *state;

    fpt->header.header_marker  = FPT_HEADER_MARKER;
    fpt->header.header_version = FPT_HEADER_VERSION;
    fpt->header.entry_version  = FPT_ENTRY_VERSION;
    fpt->header.num_of_entries = FWU_FPT_ENTRY_NUM;
    fpt->header.header_length  = FPT_HEADER_LENGTH;

    return 0;
}

/**
 * @brief
 * Test: fpt->header.header_length = 0
 *
 * @param state test state
 */
static void test_layout_parse_buffer_heder_length_is_zero(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.header_length = 0;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);
    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.header_length < sizeof(fpt->header)
 *
 * @param state test state
 */
static void test_layout_parse_buffer_header_length_less_than_min(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.header_length = sizeof(fpt->header) - 1;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);
    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.header_length = INT_MAX
 *
 * @param state test state
 */
static void test_layout_parse_buffer_header_len_max_int(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.header_length =(uint8_t) INT_MAX;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);
    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.header_lengt > IGSC_MAX_IMAGE_SIZE
 *
 * @param state test state
 */
static void test_layout_parse_buffer_header_len_more_than_max(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.header_length = (uint8_t)IGSC_MAX_IMAGE_SIZE + 1;;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: buffer_len < sizeof(fpt->header)
 *
 * @param state test state
 */
static void test_layout_parse_buffer_less_than_min(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    buffer_len = sizeof(fpt->header) - 1;
    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);
    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: buffer_len = 0
 *
 * @param state test state
 */
static void test_layout_parse_buffer_is_zero(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    buffer_len = 0;
    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);
    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: buffer_len = INT_MAX
 *
 * @param state test state
 */
static void test_layout_parse_buffer_len_max_int(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    buffer_len = INT_MAX;
    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);
    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test:  buffer_len > IGSC_MAX_IMAGE_SIZE
 *
 * @param state test state
 */
static void test_layout_parse_buffer_more_than_max(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    /* buffer_len > IGSC_MAX_IMAGE_SIZE */
    buffer_len = IGSC_MAX_IMAGE_SIZE + 1;

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test:  buffer_len < total_size
 *
 * @param state test state
 */
static void test_layout_parse_buffer_too_small(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    buffer_len = __buffer_len(fpt) - 1;

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.header_marker != FPT_HEADER_MARKER
 *
 * @param state test state
 */
static void test_layout_parse_header_bad_marker(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.header_marker = 0;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.num_of_entries < FWU_FPT_ENTRY_NUM
 *
 * @param state test state
 */
static void test_layout_parse_header_entries_too_little(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.num_of_entries = FWU_FPT_ENTRY_NUM - 1;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.num_of_entries > FPT_MAX_ENTERIES
 *
 * @param state test state
 */
static void test_layout_parse_header_entries_too_big(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.num_of_entries = FPT_MAX_ENTERIES + 1;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.header_version != FPT_HEADER_VERSION
 *
 * @param state test state
 */
static void test_layout_parser_header_bad_version(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.header_version = FPT_HEADER_VERSION - 1;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.entry_version != FPT_ENTRY_VERSION 
 *
 * @param state test state
 */
static void test_layout_parser_header_entry_bad_version(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.entry_version = FPT_ENTRY_VERSION + 1;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

/**
 * @brief
 * Test: fpt->header.header_length != FPT_HEADER_LENGTH
 *
 * @param state test state
 */
static void test_layout_parser_header_bad_length(void **state)
{
    struct gsc_fwu_img_layout layout;
    struct gsc_fwu_fpt_img *fpt = *state;
    uint32_t buffer_len;
    int ret;

    fpt->header.header_length = FPT_HEADER_LENGTH + 1;
    buffer_len = __buffer_len(fpt);

    ret = gsc_fwu_img_layout_parse(&layout, (uint8_t *)fpt, buffer_len);

    assert_true(ret != IGSC_SUCCESS);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_layout_parse_buffer_heder_length_is_zero, test_setup),
        cmocka_unit_test_setup(test_layout_parse_buffer_header_length_less_than_min, test_setup),
        cmocka_unit_test_setup(test_layout_parse_buffer_header_len_max_int, test_setup),
        cmocka_unit_test_setup(test_layout_parse_buffer_header_len_more_than_max, test_setup),
        cmocka_unit_test_setup(test_layout_parse_buffer_is_zero, test_setup),
        cmocka_unit_test_setup(test_layout_parse_buffer_less_than_min, test_setup),
        cmocka_unit_test_setup(test_layout_parse_buffer_len_max_int, test_setup),
        cmocka_unit_test_setup(test_layout_parse_buffer_more_than_max, test_setup),
        cmocka_unit_test_setup(test_layout_parse_buffer_too_small, test_setup),
        cmocka_unit_test_setup(test_layout_parse_header_bad_marker, test_setup),
        cmocka_unit_test_setup(test_layout_parse_header_entries_too_little, test_setup),
        cmocka_unit_test_setup(test_layout_parse_header_entries_too_big, test_setup),
        cmocka_unit_test_setup(test_layout_parser_header_bad_version, test_setup),
        cmocka_unit_test_setup(test_layout_parser_header_entry_bad_version, test_setup),
        cmocka_unit_test_setup(test_layout_parser_header_bad_length, test_setup)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
