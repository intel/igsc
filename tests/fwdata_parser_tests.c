/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2021 Intel Corporation
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#include "fw_data_parser.c"

#define IMAGE_SIZE 2048

static int group_setup(void **state)
{
    struct igsc_fwdata_image *img;
    struct code_partition_directory_header *header;

    *state = malloc(sizeof(*img));
    if (*state == NULL)
    {
        return -1;
    }

    header = (struct code_partition_directory_header *) malloc(IMAGE_SIZE);
    if (header == NULL)
    {
        free(*state);
        return -1;
    }

    img = *state;
    img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content = (uint8_t *)header;
    return 0;
}

static int test_setup(void **state)
{
    struct igsc_fwdata_image *img = *state;
    struct mft_header *manifest_header;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    memset((void *)dir_header, 0, IMAGE_SIZE);
    img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].size = IMAGE_SIZE;

    dir_header->header_marker = 0x44504324;
    dir_header->num_of_entries = CPD_MAX_INDEX;

    dir_header->entries[CPD_MANIFEST_INDEX].offset =  sizeof(struct code_partition_directory_header);

    manifest_header = (struct mft_header *) ((uint8_t *)dir_header +
                                             dir_header->entries[CPD_MANIFEST_INDEX].offset);
    dir_header->entries[CPD_MANIFEST_INDEX].length = (manifest_header->size - manifest_header->header_length) * 4 + sizeof(struct mft_fwdata_update_ext);

    manifest_header->header_length = sizeof(*manifest_header)/4;
    manifest_header->size = manifest_header->header_length + sizeof(struct mft_fwdata_update_ext) +
                            sizeof(struct igsc_fwdata_device_info) - 1;

    struct mft_fwdata_device_ids_ext *dev_ext = (struct mft_fwdata_device_ids_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[CPD_MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    dev_ext->extension_type = MFT_EXT_TYPE_DEVICE_IDS;
    dev_ext->extension_length = (manifest_header->size - manifest_header->header_length) * 4 - sizeof(struct mft_fwdata_update_ext);

    struct mft_fwdata_update_ext *mft_ext = (struct mft_fwdata_update_ext *)((uint8_t *)dev_ext + dev_ext->extension_length);

    mft_ext->extension_type = MFT_EXT_TYPE_FWDATA_UPDATE;
    mft_ext->extension_length = sizeof(struct mft_fwdata_update_ext);

    return 0;
}

static int group_teardown(void **state)
{
    struct igsc_fwdata_image *img = *state;

    free((void *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content);
    free(*state);

    return 0;
}

static void test_fwdata_parse_good_img(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;

    ret = image_fwdata_parse(img);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_fwdata_parse_null_img(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = NULL;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_cpd_size(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].size = sizeof(*dir_header) +
                      dir_header->num_of_entries * sizeof(dir_header->entries[0]);

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_cpd_num_of_entries(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->num_of_entries = 2;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_marker(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->header_marker = 0x44504325;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_manifest_offset(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->entries[CPD_MANIFEST_INDEX].offset = img->buffer_len - sizeof(struct mft_header);

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_manifest_offset_2(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->entries[CPD_MANIFEST_INDEX].offset = UINT16_MAX;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}


static void test_fwdata_parse_bad_public_key_offset(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->entries[CPD_MANIFEST_INDEX].offset = img->buffer_len -
                                                 sizeof(struct mft_header) -
                                                 sizeof(struct mft_rsa_3k_key);

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_signature_offset(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->entries[CPD_MANIFEST_INDEX].offset = img->buffer_len -
                                                 sizeof(struct mft_header) -
                                                 sizeof(struct mft_rsa_3k_key) -
                                                 sizeof(struct rsa_3072_pss_signature);

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_manifest_size_length(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    // set manifest_header->size < manifest_header->header_length
    struct mft_header *manifest_header = (struct mft_header *) ((uint8_t *)dir_header +
                                          dir_header->entries[CPD_MANIFEST_INDEX].offset);

    manifest_header->header_length = manifest_header->size + 1;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_manifest_length(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->entries[CPD_MANIFEST_INDEX].length = MANIFEST_SIZE_MAX_VALUE * sizeof(uint32_t) + 1;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_metadata_offset(void **state)
{
    int ret;
    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->entries[CPD_METADATA_INDEX].offset = img->buffer_len + 1;

    ret = image_fwdata_parse(img);
    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_metadata_length(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->entries[CPD_METADATA_INDEX].length = img->buffer_len + 1;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_bad_metadata_start(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    dir_header->entries[CPD_METADATA_INDEX].offset = img->buffer_len + 1;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_manifest_ext_length_underflow(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    struct mft_fwdata_device_ids_ext *dev_ext = (struct mft_fwdata_device_ids_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[CPD_MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    dev_ext->extension_length = 2;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_fwdata_parse_manifest_ext_length_overflow(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    struct mft_fwdata_device_ids_ext *dev_ext = (struct mft_fwdata_device_ids_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[CPD_MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    dev_ext->extension_length = 100000;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}


static void test_fwdata_parse_bad_manifest_device_ext_length(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    struct mft_fwdata_device_ids_ext *dev_ext = (struct mft_fwdata_device_ids_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[CPD_MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    dev_ext->extension_length = sizeof(struct mft_ext_header_with_data) + sizeof(struct igsc_fwdata_device_info) - 1;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}


static void test_fwdata_parse_bad_manifest_ext_length(void **state)
{
    int ret;

    struct igsc_fwdata_image *img = *state;
    struct code_partition_directory_header *dir_header = (struct code_partition_directory_header *)img->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;

    struct mft_fwdata_device_ids_ext *dev_ext = (struct mft_fwdata_device_ids_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[CPD_MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    struct mft_fwdata_update_ext *mft_ext = (struct mft_fwdata_update_ext *)((uint8_t *)dev_ext + dev_ext->extension_length);

    dev_ext->extension_length = sizeof(struct mft_fwdata_update_ext)-1;

    ret = image_fwdata_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_fwdata_parse_good_img, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_null_img, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_cpd_size, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_cpd_num_of_entries, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_marker, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_manifest_offset, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_manifest_offset_2, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_public_key_offset, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_signature_offset, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_manifest_size_length, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_manifest_length, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_metadata_offset, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_metadata_length, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_metadata_start, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_manifest_ext_length_underflow, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_manifest_ext_length_overflow, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_manifest_device_ext_length, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_bad_manifest_ext_length, test_setup),
        cmocka_unit_test_setup(test_fwdata_parse_good_img, test_setup),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
