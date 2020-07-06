#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#include "../lib/igsc_oprom.c"

#define IMAGE_SIZE 2048

static int group_setup(void **state)
{
    struct igsc_oprom_image *img;
    struct oprom_header_ext_v2 *header;

    *state = malloc(sizeof(*img));
    header = malloc(IMAGE_SIZE);

    memset(header, 0, IMAGE_SIZE);

    img = *state;
    img->buffer = (uint8_t *)header;

    return 0;
}

static void setup_pci_data(struct oprom_pci_data *p_d)
{
    p_d->code_type = OPROM_CODE_TYPE_CODE;
    p_d->signature = PCI_DATA_SIGNATURE;
    p_d->vendor_id = PCI_VENDOR_ID;
    p_d->device_id = PCI_DEVICE_ID;
    p_d->pci_data_structure_length = PCI_DATA_LENGTH;
    p_d->pci_data_structure_revision = PCI_DATA_REVISION;
    p_d->class_code = PCI_CLASS_CODE;
    p_d->revision_level = PCI_REVISION_LEVEL;
    p_d->last_image_indicator = PCI_LAST_IMAGE_IND_BIT;
}

static void setup_pci_header(struct oprom_header_ext_v2 *header)
{
    header->signature = ROM_SIGNATURE;
    header->subsystem = PCI_SUBSYSTEM_EFI_BOOT_SRV_DRV;
    header->machine_type = PCI_MACHINE_TYPE_X64;
    header->compression_type = PCI_COMPRESSION_TYPE_UNCOMPRESSED;
    header->signature = 0xAA55;
    header->pci_data_structure_pointer = sizeof(struct oprom_header_ext_v2);
}

static int test_setup(void **state)
{
    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header;
    struct oprom_pci_data *pci_data;
    struct mft_header *manifest_header;

    memset((void *)img->buffer, 0, IMAGE_SIZE);
    img->buffer_len = IMAGE_SIZE;

    pci_header = (struct oprom_header_ext_v2 *)img->buffer;
    setup_pci_header(pci_header);

    pci_data = (struct oprom_pci_data *)(img->buffer + pci_header->pci_data_structure_pointer);
    setup_pci_data(pci_data);

    pci_header->unofficial_payload_offset = sizeof(struct oprom_header_ext_v2) +
                                            sizeof(struct oprom_pci_data);

    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->header_marker = 0x44504324;
    dir_header->num_of_entries = MAX_INDEX;

    dir_header->entries[MANIFEST_INDEX].offset = pci_header->unofficial_payload_offset +
                      sizeof(struct code_partition_directory_header);

    manifest_header = (struct mft_header *) ((uint8_t *)dir_header +
                                             dir_header->entries[MANIFEST_INDEX].offset);
    dir_header->entries[MANIFEST_INDEX].length = sizeof(struct oprom_subsystem_device_id);

    manifest_header->header_length = sizeof(*manifest_header)/4;
    manifest_header->size = manifest_header->header_length +
                            sizeof(struct oprom_subsystem_device_id) - 1;

    struct mft_oprom_device_type_ext *dev_ext = (struct mft_oprom_device_type_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));
    dev_ext->extension_type = MFT_EXT_TYPE_DEVICE_TYPE;
    dev_ext->extension_length = sizeof(struct mft_ext_header_with_data) +
                                sizeof(struct oprom_subsystem_device_id);

    return 0;
}

static int group_teardown(void **state)
{
    struct igsc_oprom_image *img = *state;

    free((void *)img->buffer);
    free(*state);

    return 0;
}

static void test_oprom_parse_good_img(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;

    ret = image_oprom_parse(img);

    assert_true(ret == IGSC_SUCCESS);
}

static void test_oprom_parse_null_img(void **state)
{
    int ret;

    struct igsc_oprom_image *img = NULL;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}


static void test_oprom_parse_bad_header_signature(void **state)
{
    int ret;

    struct oprom_header_ext_v2    *header;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    header->signature = 0xAA56;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_header_subsystem(void **state)
{
    int ret;

    struct oprom_header_ext_v2    *header;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    header->subsystem = 0x01;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_header_machine_type(void **state)
{
    int ret;

    struct oprom_header_ext_v2    *header;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    header->machine_type = 0x01;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_header_compression_type(void **state)
{
    int ret;

    struct oprom_header_ext_v2    *header;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    header->machine_type = 0x01;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_data_structure_pointer(void **state)
{
    int ret;

    struct oprom_header_ext_v2    *header;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    header->pci_data_structure_pointer = img->buffer_len;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_data_signature(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    pci_data->signature = 0x52494351;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_data_vendor_id(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    pci_data->vendor_id = 0x8085;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_data_device_id(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    pci_data->device_id = 0x01;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_data_structure_length(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    pci_data->pci_data_structure_length = 0x19;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_data_structure_revision(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    pci_data->pci_data_structure_revision = 0x00;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_data_class_code(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    pci_data->class_code = 0x01;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_data_revision_level(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    pci_data->revision_level = 0x01;
    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_code_type(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    pci_data->code_type = 0;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_pci_size(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct oprom_pci_data *pci_data;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    pci_data = (struct oprom_pci_data *) (img->buffer + header->pci_data_structure_pointer);
    header->image_size = pci_data->image_length - 1;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_cpd_offset(void **state)
{
    int ret;

    struct oprom_header_ext_v2 *header;
    struct igsc_oprom_image *img = *state;

    header = (struct oprom_header_ext_v2 *)img->buffer;
    header->unofficial_payload_offset = img->buffer_len;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_cpd_size(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header =
                      (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    img->buffer_len = sizeof(*dir_header) +
                      dir_header->num_of_entries * sizeof(dir_header->entries[0]) + img->cpd_offset;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_cpd_num_of_entries(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->num_of_entries = 2;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_marker(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->header_marker = 0x44504325;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_manifest_offset(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->entries[MANIFEST_INDEX].offset = img->buffer_len - sizeof(struct mft_header);

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_public_key_offset(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header =
                      (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->entries[MANIFEST_INDEX].offset = img->buffer_len -
                                                 sizeof(struct mft_header) -
                                                 sizeof(struct mft_rsa_3k_key);

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_signature_offset(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header =
                      (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->entries[MANIFEST_INDEX].offset = img->buffer_len -
                                                 sizeof(struct mft_header) -
                                                 sizeof(struct mft_rsa_3k_key) -
                                                 sizeof(struct rsa_3072_pss_signature);

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_manifest_size_length(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;

    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    // set manifest_header->size < manifest_header->header_length
    struct mft_header *manifest_header = (struct mft_header *) ((uint8_t *)dir_header +
                                          dir_header->entries[MANIFEST_INDEX].offset);

    manifest_header->header_length = manifest_header->size + 1;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_manifest_length(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->entries[MANIFEST_INDEX].length = MANIFEST_SIZE_MAX_VALUE * sizeof(uint32_t) + 1;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_metadata_offset(void **state)
{
    int ret;
    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->entries[METADATA_INDEX].offset = img->buffer_len + 1;

    ret = image_oprom_parse(img);
    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_metadata_length(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->entries[METADATA_INDEX].length = img->buffer_len + 1;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_metadata_start(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;
    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    dir_header->entries[METADATA_INDEX].offset = img->buffer_len + 1;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_manifest_ext_length_underflow(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;

    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    struct mft_oprom_device_type_ext *dev_ext = (struct mft_oprom_device_type_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    dev_ext->extension_length = 2;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_manifest_ext_length_overflow(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;

    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    struct mft_oprom_device_type_ext *dev_ext = (struct mft_oprom_device_type_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    dev_ext->extension_length = 100000;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_manifest_device_ext_length(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;

    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    struct mft_oprom_device_type_ext *dev_ext = (struct mft_oprom_device_type_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    dev_ext->extension_length = sizeof(struct mft_ext_header_with_data) + sizeof(struct oprom_subsystem_device_id) - 1;

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

static void test_oprom_parse_bad_manifest_ext_length_type_signed_pkg_info(void **state)
{
    int ret;

    struct igsc_oprom_image *img = *state;
    struct oprom_header_ext_v2 *pci_header = (struct oprom_header_ext_v2 *)img->buffer;

    struct code_partition_directory_header *dir_header =
                      (struct code_partition_directory_header *)
                      (img->buffer + pci_header->unofficial_payload_offset);

    struct mft_oprom_device_type_ext *dev_ext = (struct mft_oprom_device_type_ext *)
                                                ((uint8_t *)dir_header +
                                                 dir_header->entries[MANIFEST_INDEX].offset +
                                                 sizeof(struct mft_header) +
                                                 sizeof(struct mft_rsa_3k_key) +
                                                 sizeof (struct rsa_3072_pss_signature));

    dev_ext->extension_type = MFT_EXT_TYPE_SIGNED_PACKAGE_INFO;
    dev_ext->extension_length = sizeof(struct mft_signed_package_info_ext);

    ret = image_oprom_parse(img);

    assert_true(ret != IGSC_SUCCESS);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_oprom_parse_good_img, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_null_img, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_header_signature, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_header_subsystem, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_header_machine_type, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_header_compression_type, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_data_structure_pointer, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_data_signature, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_data_vendor_id, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_data_device_id, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_data_structure_length, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_data_structure_revision, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_data_class_code, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_data_revision_level, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_code_type, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_pci_size, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_cpd_offset, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_cpd_size, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_cpd_num_of_entries, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_manifest_length, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_marker, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_manifest_offset, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_public_key_offset, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_signature_offset, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_manifest_size_length, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_metadata_offset, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_metadata_length, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_manifest_ext_length_underflow, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_manifest_ext_length_overflow, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_manifest_device_ext_length, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_bad_manifest_ext_length_type_signed_pkg_info, test_setup),
        cmocka_unit_test_setup(test_oprom_parse_good_img, test_setup),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
