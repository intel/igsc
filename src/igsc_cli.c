/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2024 Intel Corporation
 */
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef __linux__
  #include <unistd.h>
  #include <libgen.h>
#else
  #include <windows.h>
  #include <initguid.h>
#endif // __linux__

#include "gcc/config.h"
#include "msvc/config.h"

#include "igsc_lib.h"
#ifdef __linux__
#define _countof(a) (sizeof(a)/sizeof(*(a)))
static inline void gsc_msleep(uint32_t msecs)
{
    usleep(msecs * 1000);
}
#elif WIN32
static inline void gsc_msleep(uint32_t msecs)
{
    Sleep(msecs);
}
#endif /* __linux__ */


static bool verbose = false;
static bool quiet = false;
static bool use_progress_bar = false;

#define fwupd_verbose(fmt, ...) do {          \
    if (verbose && !quiet)                    \
        fprintf(stderr, fmt, ##__VA_ARGS__);  \
} while (0)

#define fwupd_error(fmt, ...) do {                     \
    if (!quiet)                                        \
        fprintf(stderr, "Error: " fmt, ##__VA_ARGS__); \
} while (0)

#define fwupd_msg(fmt, ...) do {               \
    if (!quiet)                                \
        fprintf(stdout, fmt, ##__VA_ARGS__);   \
} while (0)

#define MAX_UPDATE_IMAGE_SIZE (8*1024*1024)
#define MAX_CONNECT_RETRIES 3
#define CONNECT_RETRIES_SLEEP_MSEC 2000 /* 2 sec */

struct img {
    uint32_t size;
    uint8_t blob[0];
};


#ifdef __linux__
#ifndef igsc_strdup
#define igsc_strdup strdup
#endif /* igsc_strdup */

static inline int fopen_s(FILE **fp, const char *pathname, const char *mode)
{
    if (!fp)
    {
        return EINVAL;
    }

    errno = 0;
    *fp = fopen(pathname, mode);

    return errno;
}

static void fwupd_strerror(int errnum, char *buf, size_t buflen)
{
    if (buflen == 0)
    {
        return;
    }

    if (strerror_r(errnum, buf, buflen) != 0)
    {
         strncpy(buf, "Unknown error", buflen - 1);
         buf[buflen - 1] = '\0';
    }
}
#elif defined(WIN32)
#ifndef igsc_strdup
#define igsc_strdup _strdup
#endif /* igsc_strdup */
static void fwupd_strerror(int errnum, char *buf, size_t buflen)
{
    if (buflen == 0)
    {
        return;
    }

    if (strerror_s(buf, buflen, errnum) != 0)
    {
         strncpy_s(buf, buflen, "Unknown error", buflen - 1);
         buf[buflen - 1] = '\0';
    }
}
#endif /* __linux__ */

static void print_oem_version(const struct igsc_oem_version *version)
{
    if (version->length > IGSC_MAX_OEM_VERSION_LENGTH)
    {
        printf("Illegal OEM Version: length bigger than %u\n", version->length);
        return;
    }

    printf("OEM Version: ");
    for (int i = 0; i < version->length; i++)
    {
         printf("%x", version->version[i]);
    }
    printf("\n");
}

static void print_psc_version(const struct igsc_psc_version *version)
{
   printf("PSC Version: cfg_version: 0x%04x, date: 0x%04x\n", version->cfg_version, version->date);
}

static void print_ifr_bin_version(const struct igsc_ifr_bin_version *version)
{
    printf("IFR Version: %d.%d_%d.%d\n",
           version->major,
           version->minor,
           version->hotfix,
           version->build);
}


static void print_fw_version(const char *prefix,
                             const struct igsc_fw_version *fw_version)
{
    printf("%sFW Version: %c%c%c%c_%d.%d\n",
           prefix,
           fw_version->project[0],
           fw_version->project[1],
           fw_version->project[2],
           fw_version->project[3],
           fw_version->hotfix,
           fw_version->build);
}

static inline void print_dev_fw_version(const struct igsc_fw_version *fw_version)
{
	print_fw_version("Device: ", fw_version);
}

static inline void print_img_fw_version(const struct igsc_fw_version *fw_version)
{
	print_fw_version("Image:  ", fw_version);
}

static void print_fwdata_device_info(struct igsc_fwdata_device_info *info)
{
    printf("Vendor Id: %04X Device Id: %04X\n Subsys Vendor Id: %04X Subsys Device Id: %04X\n",
           info->vendor_id, info->device_id,
           info->subsys_vendor_id, info->subsys_device_id);
}

static void print_fwdata_version(const char *prefix,
                                 const struct igsc_fwdata_version2 *fwdata_version)
{
    printf("%sFw Data Version: Format %u, Major Version: %u, OEM Manufacturing Data Version: %u, Major VCN: %u\n \
   OEM Manufacturing Data Version FITB: %u, Flags: 0X%08x, ARB SVN: %u, ARB SVN FITB: %u\n",
           prefix,
           fwdata_version->format_version,
           fwdata_version->major_version,
           fwdata_version->oem_manuf_data_version,
           fwdata_version->major_vcn,
           (fwdata_version->flags & IGSC_FWDATA_FITB_VALID_MASK) ?
               fwdata_version->oem_manuf_data_version_fitb : 999999,
           fwdata_version->flags,
           (fwdata_version->format_version > IGSC_FWDATA_FORMAT_VERSION_1) ?
               fwdata_version->data_arb_svn : 999999,
           ((fwdata_version->format_version > IGSC_FWDATA_FORMAT_VERSION_1) &&
	    (fwdata_version->flags & IGSC_FWDATA_FITB_VALID_MASK)) ?
               fwdata_version->data_arb_svn_fitb : 999999);
}

static inline void print_dev_fwdata_version(const struct igsc_fwdata_version2 *fwdata_version)
{
    print_fwdata_version("Device: ", fwdata_version);
}

static inline void print_img_fwdata_version(const struct igsc_fwdata_version2 *fwdata_version)
{
    print_fwdata_version("Image:  ", fwdata_version);
}

const char *oprom_type_to_str(uint32_t type)
{
    if (type == IGSC_OPROM_NONE)
        return "UNKNOWN";
    if (type == IGSC_OPROM_DATA)
        return "DATA";
    if (type == IGSC_OPROM_CODE)
        return "CODE";
    return "DATA and CODE";
}

static void print_oprom_version(enum igsc_oprom_type type,
                                const struct igsc_oprom_version *oprom_version)
{
    printf("OPROM %s Version: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           oprom_type_to_str(type),
           oprom_version->version[0],
           oprom_version->version[1],
           oprom_version->version[2],
           oprom_version->version[3],
           oprom_version->version[4],
           oprom_version->version[5],
           oprom_version->version[6],
           oprom_version->version[7]);
}

static void print_oprom_device_info(const struct igsc_oprom_device_info *info)
{
    printf("Vendor Id: %04X Device Id: %04X\n",
           info->subsys_vendor_id, info->subsys_device_id);
}

static void print_oprom_device_info_4ids(struct igsc_oprom_device_info_4ids *info)
{
    printf("Vendor Id: %04X Device Id: %04X SubSystem Vendor Id: %04X SubSystem Device Id: %04X\n",
           info->vendor_id, info->device_id, info->subsys_vendor_id, info->subsys_device_id);
}

static inline void print_oprom_code_version(const struct igsc_oprom_version *oprom_version)
{
    print_oprom_version(IGSC_OPROM_CODE, oprom_version);
}

static inline void print_oprom_data_version(const struct igsc_oprom_version *oprom_version)
{
    print_oprom_version(IGSC_OPROM_DATA, oprom_version);
}

static inline void print_hw_config(const char *title, const struct igsc_hw_config *hw_config)
{
    char cfg_str[512];

    memset(cfg_str, 0, sizeof(cfg_str));
    if (igsc_hw_config_to_string(hw_config, cfg_str, sizeof(cfg_str)) > 0)
    {
        printf("%s: %s\n", title, cfg_str);
    }
}

static struct img *image_read_from_file(const char *p_path)
{
    FILE  *fp = NULL;
    struct img *img = NULL;
    long file_size;
    char err_msg[64] = {0};
    errno = 0;

    if (fopen_s(&fp, p_path, "rb") != 0 || fp == NULL)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to open file %s : %s\n", p_path, err_msg);
        goto exit;
    }

    if (fseek(fp, 0L, SEEK_END) != 0)
    {
        fwupd_verbose("Failed to get file size %s : %s\n",
                      p_path, err_msg);
        goto exit;
    }

    file_size = ftell(fp);
    if (file_size < 0)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to get file size %s : %s\n",
                      p_path, err_msg);
        goto exit;
    }

    if (file_size > IGSC_MAX_IMAGE_SIZE)
    {
        fwupd_verbose("Update image size (%ld) too large\n", file_size);
        goto exit;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to reset file position %s : %s\n",
                      p_path, err_msg);
        goto exit;
    }

    img = (struct img *)malloc((size_t)file_size + sizeof(*img));
    if (img == NULL)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to allocate memory %s\n", err_msg);
        goto exit;
    }

    if (fread(img->blob, 1, (size_t)file_size, fp) != (size_t)file_size)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to read file %s : %s\n",
                      p_path, err_msg);
        goto exit;
    }
    /* note: the size was already checked it ifts to 32bit */
    img->size = (uint32_t)file_size;

    fclose(fp);

    return img;

exit:
    free(img);
    if (fp)
    {
        fclose(fp);
    }

    return NULL;
}

static const char *translate_health_indicator(uint8_t health_indicator)
{
    switch (health_indicator) {
    case  IGSC_HEALTH_INDICATOR_HEALTHY:
        return "HEALTHY";
    case  IGSC_HEALTH_INDICATOR_DEGRADED:
        return "DEGRADED";
    case  IGSC_HEALTH_INDICATOR_CRITICAL:
        return "CRITICAL";
    case  IGSC_HEALTH_INDICATOR_REPLACE:
        return "REPLACE";
    default:
        return "UNKNOWN";
    }
}

#ifdef ENABLE_TEST_GENERIC_GFSP_API
/**
 *  This code can be used as an example of generic gfsp igsc library routine
 *  (igsc_gfsp_heci_cmd) API usage
 */
#define GFSP_MAX_TILES 4
/**
 * @brief data of the response to the get memory error mitigation status request
 *
 * @param boot_time_memory_correction_pending 0 - No pending boot time memory correction,
 *                                            1 - Pending boot time memory correction
 * @param bank_sparing_applied Bank Sparing status 0 - not applied, 1 - applied, 2 – exhausted
 * @param health_indicator contains enum gfsp_health_indicators
 * @param reserved reserved field
 * @param max_num_of_tiles max number of tiles on the card
 * @param error_mitigation_status A per tile error mitigation status
 * @param error_mitigation_status A per tile health mitigation status
 *
 */
struct gfsp_get_mem_err_mitigation_status {
    uint8_t  boot_time_memory_correction_pending;
    uint8_t  bank_sparing_applied;
    uint8_t  health_indicator; /**< enum gfsp_health_indicators */
    uint8_t  reserved;
    uint32_t max_num_of_tiles;
    uint8_t  error_mitigation_status[GFSP_MAX_TILES];
    uint8_t  health_mitigation_status[GFSP_MAX_TILES];
};
enum gfsp_cmd {
    GFSP_CORR_MEM_STAT_CMD = 1,      /**< Get memory correction status */
    GFSP_MEM_ERR_MITIG_STAT_CMD = 2, /**< Get memory error mitigation status */
    GFSP_MUN_MEM_ERR_CMD = 3,        /**< Get number of memory errors */
    GFSP_MEM_PRP_STAT_CMD = 4,       /**< Get memory PPR status */
    GFSP_MEM_ID_CMD = 5,             /**< Get memory ID */
    GFSP_SET_ECC_CFG_CMD = 8,        /**< Set ECC Configuration */
    GFSP_GET_ECC_CFG_CMD = 9,        /**< Get ECC Configuration */
};
#define MAX_MEM_ERR_MITIGATION_STATUS_RESPONSE_SIZE 256

mockable_static
int get_health_indicator(struct igsc_device_handle *handle)
{
    int ret;
    uint8_t buffer[MAX_MEM_ERR_MITIGATION_STATUS_RESPONSE_SIZE] = {0};
    struct gfsp_get_mem_err_mitigation_status *resp = (struct gfsp_get_mem_err_mitigation_status *)buffer;
    size_t actual_response_size;

    if (!handle)
    {
        fwupd_error("Illegal parameter\n");
        return EXIT_FAILURE;
    }

    /* call the generic gfsp igsc library routine to get memory health indicator */
    ret = igsc_gfsp_heci_cmd(handle, GFSP_MEM_ERR_MITIG_STAT_CMD, NULL, 0, buffer,
                             sizeof(buffer), &actual_response_size);

    if (ret)
    {
        fwupd_error("Failed to get memory health indicator, library return code %d\n", ret);
        return EXIT_FAILURE;
    }
    if (actual_response_size < sizeof(*resp))
    {
        fwupd_error("Failed to receive memory health indicator, expected %zu bytes, got %zu byte\n",
                    sizeof(*resp), actual_response_size);
        return EXIT_FAILURE;
    }

    printf("received %zu bytes, number of tiles: %u\n", actual_response_size, resp->max_num_of_tiles);
    printf("memory health indicator: 0x%x (%s)\n", resp->health_indicator,
           translate_health_indicator(resp->health_indicator));

    return ret;
}

#else /* ENABLE_TEST_GENERIC_GFSP_API */
mockable_static
int get_health_indicator(struct igsc_device_handle *handle)
{
    int ret;
    uint8_t health_indicator;
    unsigned int retries = 0;

    if (!handle)
    {
        fwupd_error("Illegal parameter\n");
        return EXIT_FAILURE;
    }

    /* call the igsc library routine to get memory health indicator */
    while ((ret = igsc_gfsp_get_health_indicator(handle, &health_indicator)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to get memory health indicator, library return code %d\n", ret);
        return EXIT_FAILURE;
    }

    printf("memory health indicator: 0x%x (%s)\n", health_indicator,
           translate_health_indicator(health_indicator));

    return ret;
}

#endif /* ENABLE_TEST_GENERIC_GFSP_API */

mockable_static
int get_first_device_info(struct igsc_device_info *dev_info)
{
    struct igsc_device_iterator *iter;
    int ret;

    ret = igsc_device_iterator_create(&iter);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot create device iterator\n");
        return EXIT_FAILURE;
    }

    ret = igsc_device_iterator_next(iter, dev_info);
    igsc_device_iterator_destroy(iter);

    return ret;
}

static int get_first_device(char **device_path)
{
    struct igsc_device_iterator *iter;
    struct igsc_device_info info;
    int ret;

    ret = igsc_device_iterator_create(&iter);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot create device iterator\n");
        return EXIT_FAILURE;
    }

    info.name[0] = '\0';
    ret = igsc_device_iterator_next(iter, &info);
    if (ret == IGSC_SUCCESS)
    {
        *device_path = igsc_strdup(info.name);
    }
    igsc_device_iterator_destroy(iter);

    return ret;
}

#define PERCENT_100 100
static void progress_bar_func(uint32_t done, uint32_t total, void *ctx)
{
    char buffer[PERCENT_100 + 1];
    uint32_t percent = (done * PERCENT_100) / total;

    (void)ctx; /* unused */

    memset(buffer, ' ', sizeof(buffer));
    printf("\r                       %s", buffer);

    if (percent > PERCENT_100)
    {
        percent = PERCENT_100;
    }

    if (percent > 0)
    {
        memset(buffer, '#', percent);
    }

    if (percent < PERCENT_100)
    {
        memset(buffer + percent, ' ', PERCENT_100 - percent);
    }

    buffer[PERCENT_100] = '\0';

    printf("\rProgress %d/%d:%2d%%:[%s]", done, total, percent, buffer);
    fflush(stdout);
}

static void progress_percentage_func(uint32_t done, uint32_t total, void *ctx)
{
    uint32_t percent = (done * PERCENT_100) / total;

   (void)ctx; /* unused */

    if (percent > PERCENT_100)
    {
        percent = PERCENT_100;
    }

    printf("\r                    ");
    printf("\rProgress %d/%d:%2d%%", done, total, percent);
    fflush(stdout);
}


#define ERROR_BAD_ARGUMENT (-1)

static bool arg_is_token(const char *arg, const char *token)
{
    size_t arg_len = strlen(arg);
    size_t token_len = strlen(token);

    return (arg_len == token_len) && !strncmp(arg, token, token_len);
}

static bool arg_is_quiet(const char *arg)
{
    return arg_is_token(arg, "-q") ||
           arg_is_token(arg, "--quiet");
}

static bool arg_is_image(const char *arg)
{
    return arg_is_token(arg, "-i") ||
           arg_is_token(arg, "--image");
}

static bool arg_is_payload(const char *arg)
{
    return arg_is_token(arg, "-p") ||
           arg_is_token(arg, "--payload");
}

static bool arg_is_flags(const char *arg)
{
    return arg_is_token(arg, "-f") ||
           arg_is_token(arg, "--flags");
}

static bool arg_is_type(const char *arg)
{
    return arg_is_token(arg, "-t") ||
           arg_is_token(arg, "--type");
}

static bool arg_is_vr_config(const char *arg)
{
    return arg_is_token(arg, "vr-config");
}

static bool arg_is_fan_table(const char *arg)
{
    return arg_is_token(arg, "fan-table");
}

static bool arg_is_device(const char *arg)
{
    return arg_is_token(arg, "-d") ||
           arg_is_token(arg, "--device");
}

static bool arg_is_allow(const char *arg)
{
    return arg_is_token(arg, "-a") ||
           arg_is_token(arg, "--allow-downgrade");
}

static bool arg_is_force(const char *arg)
{
    return arg_is_token(arg, "-f") ||
           arg_is_token(arg, "--force");
}

static bool arg_is_info(const char *arg)
{
    return arg_is_token(arg, "-i") ||
           arg_is_token(arg, "--info");
}

static bool arg_is_tile(const char *arg)
{
    return arg_is_token(arg, "-t") ||
           arg_is_token(arg, "--tile");
}

static bool arg_is_test(const char *arg)
{
    return arg_is_token(arg, "-r") ||
           arg_is_token(arg, "--test");
}

static bool arg_is_check(const char *arg)
{
    return arg_is_token(arg, "-c") ||
           arg_is_token(arg, "--check");
}

static bool arg_is_ecc_config(const char *arg)
{
    return arg_is_token(arg, "-e") ||
           arg_is_token(arg, "--ecc-config");
}

static bool arg_is_cmd(const char *arg)
{
    return arg_is_token(arg, "--cmd");
}

static bool arg_is_in(const char *arg)
{
    return arg_is_token(arg, "--in");
}

static bool arg_is_out(const char *arg)
{
    return arg_is_token(arg, "--out");
}

/* prevent optimization
 * FIXME: try to use:
 *   __attribute__((optimize("O0")))
 *   or
 *  __attribute__((__used__));
 */
static inline bool arg_next(int *_argc, char **_argv[])
{
    int argc = *_argc;
    char **argv = *_argv;

    /* last one */
    if (argc == 0)
        return false;

    argc--;
    argv++;

    *_argc = argc;
    *_argv = argv;

    return argc != 0;
}

typedef int (*gsc_op)(int argc, char *argv[]);

struct gsc_op {
    const char *name;
    gsc_op    op;
    const char *usage[9]; /* up to 8 subcommands*/
    const char  *help;  /* help */
};


static inline void print_device_fw_status(struct igsc_device_handle *handle)
{
    fwupd_msg("Firmware status: %s (0x%x)\n",
              igsc_translate_firmware_status(igsc_get_last_firmware_status(handle)),
              igsc_get_last_firmware_status(handle));
}

mockable_static
int iaf_psc_update(const char *device_path, const char *image_path)
{
    struct img *img = NULL;
    struct igsc_device_handle handle;
    char *device_path_found = NULL;
    igsc_progress_func_t progress_func = NULL;
    int ret;

    memset(&handle, 0, sizeof(handle));

    if (!device_path)
    {
        if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
            device_path_found == NULL)
        {
            fwupd_error("No device to update\n");
            return EXIT_FAILURE;
        }
        device_path = device_path_found;
    }

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        ret = EXIT_FAILURE;
        fwupd_error("Failed to read :%s\n", image_path);
        goto exit;
    }

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret)
    {
        fwupd_error("Cannot initialize device: %s\n", device_path);
        goto exit;
    }

    if (!quiet)
    {
        if (use_progress_bar)
        {
            progress_func = progress_bar_func;
        }
        else
        {
            progress_func = progress_percentage_func;
        }
    }

    ret = igsc_iaf_psc_update(&handle, img->blob, img->size,
                              progress_func, NULL);

    /* new line after progress bar */
    if (!quiet)
    {
        printf("\n");
    }
    if (ret)
    {
        fwupd_error("Update process failed\n");
        print_device_fw_status(&handle);
    }

exit:
    (void)igsc_device_close(&handle);

    free(img);
    free(device_path_found);
    return ret;

}

mockable_static
int firmware_check_hw_config(struct igsc_device_handle *handle, const struct img *img)
{
    struct igsc_hw_config device_hw_config;
    struct igsc_hw_config image_hw_config;
    int ret;
    unsigned int retries = 0;

    memset(&device_hw_config, 0, sizeof(device_hw_config));
    memset(&image_hw_config, 0, sizeof(image_hw_config));

    while ((ret = igsc_device_hw_config(handle, &device_hw_config)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret == IGSC_ERROR_NOT_SUPPORTED)
    {
        /* if firmware does not support hw_config command - don't check hw config matching */
        return IGSC_SUCCESS;
    }
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    ret = igsc_image_hw_config(img->blob, img->size, &image_hw_config);
    if (ret != IGSC_SUCCESS && ret != IGSC_ERROR_NOT_SUPPORTED)
    {
        print_device_fw_status(handle);
        return ret;
    }

    return igsc_hw_config_compatible(&image_hw_config, &device_hw_config);
}


mockable_static
int firmware_update(const char *device_path,
                    const char *image_path,
                    bool allow_downgrade,
                    bool force_update)
{
    struct img *img = NULL;
    struct igsc_device_handle handle;
    struct igsc_fw_version device_fw_version;
    struct igsc_fw_version image_fw_version;
    char *device_path_found = NULL;
    igsc_progress_func_t progress_func = NULL;
    int ret;
    uint8_t cmp;
    struct igsc_fw_update_flags flags = {0};
    unsigned int retries;

    memset(&handle, 0, sizeof(handle));

    if (!device_path)
    {
        if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
            device_path_found == NULL)
        {
            fwupd_error("No device to update\n");
            return EXIT_FAILURE;
        }
        device_path = device_path_found;
    }

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        ret = EXIT_FAILURE;
        fwupd_error("Failed to read :%s\n", image_path);
        goto exit;
    }

    memset(&image_fw_version, 0, sizeof(image_fw_version));
    ret = igsc_image_fw_version(img->blob, img->size, &image_fw_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot retrieve firmware version from image: %s\n", image_path);
        goto exit;
    }

    print_img_fw_version(&image_fw_version);

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret)
    {
        fwupd_error("Cannot initialize device: %s\n", device_path);
        goto exit;
    }

    retries = 0;
    memset(&device_fw_version, 0, sizeof(device_fw_version));
    while ((ret = igsc_device_fw_version(&handle, &device_fw_version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
            fwupd_error("Permission denied: missing required credentials to access the device: %s\n", device_path);
        }
        else
        {
            fwupd_error("Cannot retrieve firmware version from device: %s\n", device_path);
            print_device_fw_status(&handle);
        }
        goto exit;
    }
    print_dev_fw_version(&device_fw_version);

    cmp = igsc_fw_version_compare(&image_fw_version, &device_fw_version);
    switch (cmp)
    {
    case IGSC_VERSION_NEWER:
        break;
    case IGSC_VERSION_NOT_COMPATIBLE:
        fwupd_error("Firmware version is not compatible with the installed one\n");
        ret = EXIT_FAILURE;
        goto exit;
    case IGSC_VERSION_OLDER:
        /* fall through */
    case IGSC_VERSION_EQUAL:
        if (!allow_downgrade)
        {
            fwupd_error("In order to update run with -a | --allow-downgrade\n");
            ret = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }
        break;
    default:
        fwupd_error("Firmware version error in comparison\n");
        ret = EXIT_FAILURE;
        goto exit;
    }

    if (!quiet)
    {
        if (use_progress_bar)
        {
            progress_func = progress_bar_func;
        }
        else
        {
            progress_func = progress_percentage_func;
        }
    }

    ret = firmware_check_hw_config(&handle, img);
    if (ret == IGSC_ERROR_INCOMPATIBLE)
    {
        fwupd_error("The firmware image in %s is incompatible with the device %s\n",
                    image_path, device_path);
        ret = EXIT_FAILURE;
        goto exit;
    }
    if (ret != IGSC_SUCCESS)
    {
        ret = EXIT_FAILURE;
        goto exit;
    }

    if (force_update)
    {
        flags.force_update = 1;
    }
    ret = igsc_device_fw_update_ex(&handle, img->blob, img->size,
                                   progress_func, NULL, flags);

    /* new line after progress bar */
    if (!quiet)
    {
        printf("\n");
    }
    if (ret)
    {
        fwupd_error("Update process failed\n");
        print_device_fw_status(&handle);
    }
    /* delay between the update and version retrieve */
#define GSC_DELAY_AFTER_FW_UPDATE_MSEC 2000
    gsc_msleep(GSC_DELAY_AFTER_FW_UPDATE_MSEC);

    retries = 0;
    while ((ret = igsc_device_fw_version(&handle, &device_fw_version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot retrieve firmware version from device: %s\n", device_path);
        print_device_fw_status(&handle);
        goto exit;
    }
    print_dev_fw_version(&device_fw_version);

    /* check the new version */
    if (memcmp(&image_fw_version, &device_fw_version, sizeof(struct igsc_fw_version)))
    {
        fwupd_error("After the update fw version wasn't updated on the device\n");
        ret = EXIT_FAILURE;
        goto exit;
    }

exit:
    (void)igsc_device_close(&handle);

    free(img);
    free(device_path_found);
    return ret;
}

mockable_static
int firmware_version(const char *device_path)
{
    struct igsc_device_handle handle;
    struct igsc_fw_version fw_version;
    int ret;
    unsigned int retries = 0;

    memset(&handle, 0, sizeof(handle));
    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot initialize device: %s\n", device_path);
        goto exit;
    }

    memset(&fw_version, 0, sizeof(fw_version));
    while ((ret = igsc_device_fw_version(&handle, &fw_version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
           fwupd_error("Permission denied: missing required credentials to access the device %s\n", device_path);
        }
        else
        {
            fwupd_error("Cannot retrieve firmware version from device: %s\n", device_path);
            print_device_fw_status(&handle);
        }
        goto exit;
    }

    print_dev_fw_version(&fw_version);

exit:
    (void)igsc_device_close(&handle);
    return ret;
}

mockable_static
int arbsvn_commit(struct igsc_device_handle *handle)
{
    int ret;
    uint8_t fw_error = 0;
    unsigned int retries = 0;

    while ((ret = igsc_device_commit_arb_svn(handle, &fw_error)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }

    if (ret == IGSC_SUCCESS)
    {
       printf("ARB SVN Commit succeeded\n");
    }
    else
    {
       fwupd_error("ARB SVN Commit failed with return value %d, firmware error is %u\n",
                   ret, fw_error);
    }
    return ret;
}

mockable_static
int arbsvn_get_min_allowed_svn(struct igsc_device_handle *handle)
{
    int ret;
    uint8_t min_allowed_svn;
    unsigned int retries = 0;

    while ((ret = igsc_device_get_min_allowed_arb_svn(handle, &min_allowed_svn)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret == IGSC_SUCCESS)
    {
       printf("Minimal allowed ARB SVN is %u\n", min_allowed_svn);
    }
    else
    {
       fwupd_error("Failed to retrieve Minimal allowed ARB SVN, return value is %d\n", ret);
    }
    return ret;
}

mockable_static
int oem_version(struct igsc_device_handle *handle)
{
    struct igsc_oem_version version;
    int ret;
    unsigned int retries = 0;

    memset(&version, 0, sizeof(version));
    while ((ret = igsc_device_oem_version(handle, &version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
           fwupd_error("Permission denied: missing required credentials to access the device\n");
        }
        else {
            fwupd_error("Cannot retrieve OEM version from device\n");
            print_device_fw_status(handle);
        }
        return EXIT_FAILURE;
    }

    print_oem_version(&version);

    return ret;
}

mockable_static
int iaf_psc_version(struct igsc_device_handle *handle)
{
    struct igsc_psc_version version;
    int ret;
    unsigned int retries = 0;

    memset(&version, 0, sizeof(version));
    while ((ret = igsc_device_psc_version(handle, &version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
           fwupd_error("Permission denied: missing required credentials to access the device\n");
        }
        else {
            fwupd_error("Cannot retrieve PSC version from device\n");
            print_device_fw_status(handle);
        }
        return EXIT_FAILURE;
    }

    print_psc_version(&version);
    return ret;
}

mockable_static
int image_version(const char *image_path)
{
    struct img *img = NULL;
    struct igsc_fw_version fw_version;
    int ret;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        ret = EXIT_FAILURE;
        goto exit;
    }

    ret = igsc_image_fw_version(img->blob, img->size, &fw_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot retrieve firmware version from image: %s\n", image_path);
        goto exit;
    }
    print_img_fw_version(&fw_version);

exit:
    free(img);
    return ret;
}

static int do_firmware_version(int argc, char *argv[])
{
    char *device_path_found = NULL;

    if (argc == 2)
    {
        if (arg_is_device(argv[0]))
        {
            return firmware_version(argv[1]);
        }
        if (arg_is_image(argv[0]))
        {
            return image_version(argv[1]);
        }
        fwupd_error("Wrong argument %s\n", argv[0]);
        return ERROR_BAD_ARGUMENT;
    }
    else if (argc == 0)
    {
        int ret;

        if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
            device_path_found == NULL)
        {
            fwupd_error("No device or image\n");
            return EXIT_FAILURE;
        }

        ret = firmware_version(device_path_found);
        free(device_path_found);
        return ret;
    }
    fwupd_error("Wrong number of arguments\n");
    return ERROR_BAD_ARGUMENT;
}

static int image_hw_config(const char *image_path, struct igsc_hw_config *hw_config)
{
    struct img *img = NULL;
    int ret;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        ret = EXIT_FAILURE;
        goto exit;
    }

    ret = igsc_image_hw_config(img->blob, img->size, hw_config);
    if (ret == IGSC_ERROR_NOT_SUPPORTED)
    {
        fwupd_error("config option is not available\n");
    }
    else if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Error in the image file\n");
    }

exit:
    free(img);
    return ret;
}

static int firmware_hw_config(const char *device_path, struct igsc_hw_config *hw_config)
{
    struct igsc_device_handle handle;
    int ret;
    unsigned int retries = 0;

    memset(&handle, 0, sizeof(handle));
    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot initialize device: %s\n", device_path);
        goto exit;
    }

    while ((ret = igsc_device_hw_config(&handle, hw_config)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret == IGSC_ERROR_NOT_SUPPORTED)
    {
        fwupd_error("config option is not available\n");
    }
    if (ret)
    {
        print_device_fw_status(&handle);
    }
exit:
    (void)igsc_device_close(&handle);
    return ret;
}

static int do_firmware_hw_config(int argc, char *argv[])
{
    const char *device_path = NULL;
    char *device_path_found = NULL;
    const char *image_path = NULL;
    struct igsc_hw_config dev_hw_config;
    struct igsc_hw_config img_hw_config;
    bool check = false;
    int ret;

    if (argc == 0)
    {
        goto no_args;
    }

    if (argc > 5)
    {
        fwupd_error("Wrong number of arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    do
    {
        if (arg_is_check(argv[0]))
        {
            check = true;
        }
        else if (arg_is_device(argv[0]))
        {
            if (device_path)
            {
                fwupd_error("duplicated argument\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device to supplied\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_image(argv[0]))
        {
            if (image_path)
            {
                fwupd_error("duplicated argument\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No image file supplied\n");
                return ERROR_BAD_ARGUMENT;
            }
            image_path = argv[0];
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    }
    while(arg_next(&argc, &argv));

no_args:
    if (check)
    {
        if (image_path == NULL)
        {
            fwupd_error("No image file supplied\n");
            return ERROR_BAD_ARGUMENT;
        }

        if (device_path == NULL)
        {
            if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
                device_path_found == NULL)
            {
                ret = EXIT_FAILURE;
                fwupd_error("No device to check\n");
                goto out;
            }
            device_path = device_path_found;
        }

        ret = image_hw_config(image_path, &img_hw_config);
        if (ret != IGSC_SUCCESS)
        {
            fwupd_error("Failed to retrieve hw config from the image %s\n", image_path);
            goto out;
        }

        ret = firmware_hw_config(device_path, &dev_hw_config);
        if (ret != IGSC_SUCCESS)
        {
            fwupd_error("Failed to retrieve hw config from the device %s\n", device_path);
            goto out;
        }

        ret = igsc_hw_config_compatible(&img_hw_config, &dev_hw_config);
        if (ret == IGSC_ERROR_INCOMPATIBLE)
        {
            fwupd_error("The firmware image in %s is incompatible with the device %s\n",
                        image_path, device_path);
            ret = EXIT_FAILURE;
        }
        else if (ret != IGSC_SUCCESS)
        {
            fwupd_error("hw configuration comparison failure %s %s %d\n", image_path, device_path, ret);
            ret = EXIT_FAILURE;
            goto out;
        }

        print_hw_config("image", &img_hw_config);
        print_hw_config("device",  &dev_hw_config);
    }
    else
    {
        ret = EXIT_SUCCESS;
        if (device_path == NULL && image_path == NULL)
        {
            if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
                device_path_found == NULL)
            {
                ret = EXIT_FAILURE;
                fwupd_error("No device to check\n");
                goto out;
            }
            device_path = device_path_found;
        }

        if (image_path)
        {
            ret = image_hw_config(image_path, &img_hw_config);
            if (ret != IGSC_SUCCESS)
            {
                goto out;
            }
            print_hw_config("image", &img_hw_config);
        }

        if (device_path)
        {
            ret = firmware_hw_config(device_path, &dev_hw_config);
            if (ret != IGSC_SUCCESS)
            {
                goto out;
            }
            print_hw_config("device", &dev_hw_config);
        }
    }

out:
    free(device_path_found);
    return ret;
}


static int do_iaf_psc_update(int argc, char *argv[])
{
    const char *device_path = NULL;
    const char *image_path = NULL;

    if (argc <= 0)
    {
        fwupd_error("No image to update\n");
        return ERROR_BAD_ARGUMENT;
    }

    do
    {
        if (arg_is_quiet(argv[0]))
        {
            quiet = true;
            continue;
        }
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_image(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No image to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            image_path = argv[0];
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while(arg_next(&argc, &argv));

    if (image_path)
    {
        return iaf_psc_update(device_path, image_path);
    }

    fwupd_error("No image to update\n");
    return ERROR_BAD_ARGUMENT;
}

static int do_firmware_update(int argc, char *argv[])
{
    bool force_update = false;
    bool allow_downgrade = false;
    const char *device_path = NULL;
    const char *image_path = NULL;

    if (argc <= 0)
    {
        fwupd_error("No image to update\n");
        return ERROR_BAD_ARGUMENT;
    }

    do
    {
        if (arg_is_allow(argv[0]))
        {
            allow_downgrade = true;
            continue;
        }
        if (arg_is_quiet(argv[0]))
        {
            quiet = true;
            continue;
        }
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_image(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No image to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            image_path = argv[0];
        }
        else if (arg_is_force(argv[0]))
        {
            force_update = true;
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while(arg_next(&argc, &argv));

    if (image_path)
    {
        return firmware_update(device_path, image_path, allow_downgrade, force_update);
    }

    fwupd_error("No image to update\n");
    return ERROR_BAD_ARGUMENT;
}

mockable_static
int firmware_status(uint32_t index, const char *device_path)
{
    struct igsc_device_handle handle;
    uint32_t fw_status = 0;
    int ret;

    memset(&handle, 0, sizeof(handle));
    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot initialize device: %s\n", device_path);
        goto exit;
    }

    ret = igsc_read_fw_status_reg(&handle, index, &fw_status);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot retrieve firmware status from device: %s, returned %d\n",
                    device_path, ret);
        goto exit;
    }

    printf("Firmware Status[%u] = 0x%x\n", index, fw_status);

exit:
    if (ret != IGSC_SUCCESS)
    {
        fwupd_verbose("last firmware transaction result: %s(%d)\n",
                      igsc_translate_firmware_status(igsc_get_last_firmware_status(&handle)),
                      igsc_get_last_firmware_status(&handle));
    }

    (void)igsc_device_close(&handle);
    return ret;
}

static int do_firmware_status(int argc, char *argv[])
{
    uint32_t index;
    char *device_path_found = NULL;

    if (argc == 0)
    {
        fwupd_error("Wrong number of arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    if (arg_is_token(argv[0], "0"))
    {
       index = 0;
    }
    else if (arg_is_token(argv[0], "1"))
    {
       index = 1;
    }
    else if (arg_is_token(argv[0], "2"))
    {
       index = 2;
    }
    else if (arg_is_token(argv[0], "3"))
    {
       index = 3;
    }
    else if (arg_is_token(argv[0], "4"))
    {
       index = 4;
    }
    else if (arg_is_token(argv[0], "5"))
    {
       index = 5;
    }
    else
    {
       fwupd_error("Wrong argument %s\n", argv[0]);
       return ERROR_BAD_ARGUMENT;
    }

    if (argc == 3)
    {
        if (arg_is_device(argv[1]))
        {
            return firmware_status(index, argv[2]);
        }
        fwupd_error("Wrong argument %s\n", argv[1]);
        return ERROR_BAD_ARGUMENT;
    }
    else if (argc == 1)
    {
        int ret;

        if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
            device_path_found == NULL)
        {
            fwupd_error("No device found\n");
            return EXIT_FAILURE;
        }

        ret = firmware_status(index, device_path_found);
        free(device_path_found);
        return ret;
    }
    fwupd_error("Wrong number of arguments\n");
    return ERROR_BAD_ARGUMENT;
}

static int do_firmware(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "version"))
    {
        return do_firmware_version(argc, argv);
    }

    if (arg_is_token(sub_command, "status"))
    {
        return do_firmware_status(argc, argv);
    }

    if (arg_is_token(sub_command, "update"))
    {
        return do_firmware_update(argc, argv);
    }

    if (arg_is_token(sub_command, "hwconfig"))
    {
        return do_firmware_hw_config(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);
    return ERROR_BAD_ARGUMENT;
}

mockable_static
int oprom_device_version(const char *device_path,
                         enum igsc_oprom_type igsc_oprom_type)
{
    struct igsc_oprom_version oprom_version;
    struct igsc_device_handle handle;
    int ret;
    unsigned int retries = 0;

    memset(&handle, 0, sizeof(handle));
    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to initialize device: %s\n", device_path);
        return ret;
    }

    memset(&oprom_version, 0, sizeof(oprom_version));
    while ((ret = igsc_device_oprom_version(&handle, igsc_oprom_type, &oprom_version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
            fwupd_error("Permission denied: missing required credentials to access the device %s\n", device_path);
        }
        else
        {
            fwupd_error("Failed to get oprom version from device: %s\n", device_path);
            print_device_fw_status(&handle);
        }
        goto exit;
    }

    print_oprom_version(igsc_oprom_type, &oprom_version);

exit:
    (void)igsc_device_close(&handle);
    return ret;
}

mockable_static
int oprom_image_version(const char *image_path, enum igsc_oprom_type type)
{
    struct img *img = NULL;
    struct igsc_oprom_image *oimg = NULL;
    struct igsc_oprom_version oprom_version;
    uint32_t img_type;
    int ret;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        return EXIT_FAILURE;
    }

    ret = igsc_image_oprom_init(&oimg, img->blob, img->size);
    if (ret == IGSC_ERROR_BAD_IMAGE)
    {
        fwupd_error("Invalid image format: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_type(oimg, &img_type);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse oprom type from image: %s\n",
                    image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if ((type & img_type) == 0)
    {
        fwupd_error("Image type is %s expecting %s\n",
                    oprom_type_to_str(img_type),
                    oprom_type_to_str(type));
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_version(oimg, type, &oprom_version);
    if (ret == IGSC_SUCCESS)
    {
        print_oprom_version(type, &oprom_version);
    }
    else
    {
        fwupd_error("Failed to get oprom bersion from image: %s\n", image_path);
    }

out:
    igsc_image_oprom_release(oimg);
    free(img);

    return ret;
}

mockable_static
int oprom_code_image_supported_devices(const char *image_path)
{
    struct img *img = NULL;
    struct igsc_oprom_image *oimg = NULL;
    uint32_t img_type;
    int ret;
    uint32_t count;
    struct igsc_oprom_device_info_4ids *devices_4ids = NULL;
    bool has_4ids_extension = false;
    bool has_2ids_extension = false;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        return EXIT_FAILURE;
    }

    ret = igsc_image_oprom_init(&oimg, img->blob, img->size);
    if (ret == IGSC_ERROR_BAD_IMAGE)
    {
        fwupd_error("Invalid image format: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_type(oimg, &img_type);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get oprom type from image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if ((IGSC_OPROM_CODE & img_type) == 0)
    {
        fwupd_error("Image type is %s expecting %s\n",
                    oprom_type_to_str(img_type),
                    oprom_type_to_str(IGSC_OPROM_DATA));
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_has_4ids_extension(oimg,
                                              IGSC_OPROM_CODE,
                                              &has_4ids_extension);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to retrieve the 4ids status of the image: %d\n", ret);
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_has_2ids_extension(oimg, &has_2ids_extension);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to retrieve the 2ids status of the image: %d\n", ret);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (has_4ids_extension && has_2ids_extension)
    {
        fwupd_error("Illegal image %s, includes both 2ids and 4ids oprom extensions\n",
                    image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (has_4ids_extension)
    {
        ret = igsc_image_oprom_count_devices_typed(oimg, IGSC_OPROM_CODE, &count);
        if (ret != IGSC_SUCCESS)
        {
            fwupd_error("Failed to count supported devices on image: %s, returned %d\n",
                        image_path, ret);
            ret = EXIT_FAILURE;
            goto out;
        }
    }
    else
    {
        fwupd_msg("OPROM Code image does not have the supported devices extension\n");
        ret = EXIT_SUCCESS;
        goto out;
    }

    fwupd_verbose("Found %d supported devices in image %s\n", count, image_path);

    if (count == 0)
    {
       fwupd_msg("Image %s has empty supported devices list\n", image_path);
       ret = EXIT_SUCCESS;
       goto out;
    }

    devices_4ids = calloc(count, sizeof(struct igsc_oprom_device_info_4ids));
    if (devices_4ids == NULL) {
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_supported_devices_typed(oimg, IGSC_OPROM_CODE, devices_4ids, &count);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get %d supported devices from image: %s, ret %d\n",
                    count, image_path, ret);
        ret = EXIT_FAILURE;
        goto out;
    }
    fwupd_verbose("Retrieved %d supported devices in image %s\n", count, image_path);

    fwupd_msg("OPROM Code supported devices:\n");
    for (unsigned int i = 0; i < count; i++)
    {
        print_oprom_device_info_4ids(&devices_4ids[i]);
    }

out:
    igsc_image_oprom_release(oimg);
    free(img);
    free(devices_4ids);

    return ret;

}

mockable_static
int oprom_data_image_supported_devices(const char *image_path)
{
    struct img *img = NULL;
    struct igsc_oprom_image *oimg = NULL;
    uint32_t img_type;
    int ret;
    unsigned int i;
    uint32_t count;
    struct igsc_oprom_device_info *devices = NULL;
    struct igsc_oprom_device_info_4ids *devices_4ids = NULL;
    bool has_4ids_extension;
    bool has_2ids_extension;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        return EXIT_FAILURE;
    }

    ret = igsc_image_oprom_init(&oimg, img->blob, img->size);
    if (ret == IGSC_ERROR_BAD_IMAGE)
    {
        fwupd_error("Invalid image format: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_type(oimg, &img_type);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get oprom type from image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if ((IGSC_OPROM_DATA & img_type) == 0)
    {
        fwupd_error("Image type is %s expecting %s\n",
                    oprom_type_to_str(img_type),
                    oprom_type_to_str(IGSC_OPROM_DATA));
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_has_4ids_extension(oimg,
                                              IGSC_OPROM_DATA,
                                              &has_4ids_extension);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to retrieve the 4ids status of the image: %d\n", ret);
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_has_2ids_extension(oimg, &has_2ids_extension);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to retrieve the 2ids status of the image: %d\n", ret);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (has_4ids_extension && has_2ids_extension)
    {
        fwupd_error("Illegal image %s, includes both 2ids and 4ids oprom extensions\n",
                    image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (has_4ids_extension)
    {
        ret = igsc_image_oprom_count_devices_typed(oimg, IGSC_OPROM_DATA, &count);
    }
    else if (has_2ids_extension)
    {
        ret = igsc_image_oprom_count_devices(oimg, &count);
    }
    else
    {
        fwupd_msg("OPROM Data image does not have the supported devices extension\n");
        ret = EXIT_SUCCESS;
        goto out;
    }

    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to count supported devices on image: %s\n",
                    image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    fwupd_verbose("Found %d supported devices in image %s\n", count, image_path);

    if (count == 0)
    {
       fwupd_msg("Image %s has empty supported devices list\n", image_path);
       ret = EXIT_SUCCESS;
       goto out;
    }

    if (has_4ids_extension)
    {
        devices_4ids = calloc(count, sizeof(struct igsc_oprom_device_info_4ids));
        if (devices_4ids == NULL) {
            fwupd_error("Out of memory\n");
            ret = EXIT_FAILURE;
            goto out;
        }

        ret = igsc_image_oprom_supported_devices_typed(oimg, IGSC_OPROM_DATA,
                                                       devices_4ids, &count);
    }
    else
    {
        devices = calloc(count, sizeof(struct igsc_oprom_device_info));
        if (devices == NULL) {
            fwupd_error("Out of memory\n");
            ret = EXIT_FAILURE;
            goto out;
        }

        ret = igsc_image_oprom_supported_devices(oimg, devices, &count);
    }
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get %d supported devices from image: %s, ret %d, has_4ids_extension %u\n",
                    count, image_path, ret, has_4ids_extension);
        ret = EXIT_FAILURE;
        goto out;
    }
    fwupd_verbose("Retrieved %d supported devices in image %s\n", count, image_path);

    fwupd_msg("OPROM Data supported devices:\n");
    for (i = 0; i < count; i++)
    {
         if (has_4ids_extension)
         {
             print_oprom_device_info_4ids(&devices_4ids[i]);
         }
         else
         {
             print_oprom_device_info(&devices[i]);
         }
    }

out:
    igsc_image_oprom_release(oimg);
    free(img);
    free(devices);
    free(devices_4ids);

    return ret;
}

static int do_oprom_data_supported_devices(int argc, char *argv[])
{
    if (argc == 2)
    {
        if (arg_is_image(argv[0]))
        {
            return oprom_data_image_supported_devices(argv[1]);
        }
        fwupd_error("Wrong argument %s\n", argv[0]);
        return ERROR_BAD_ARGUMENT;
    }

    fwupd_error("Wrong number of arguments\n");
    return ERROR_BAD_ARGUMENT;
}

static int do_oprom_code_supported_devices(int argc, char *argv[])
{
    if (argc == 2)
    {
        if (arg_is_image(argv[0]))
        {
            return oprom_code_image_supported_devices(argv[1]);
        }
        fwupd_error("Wrong argument %s\n", argv[0]);
        return ERROR_BAD_ARGUMENT;
    }

    fwupd_error("Wrong number of arguments\n");
    return ERROR_BAD_ARGUMENT;
}

static int do_oprom_version(int argc, char *argv[], enum igsc_oprom_type type)
{
    char *device_path_found = NULL;

    if (argc == 2)
    {
        if (arg_is_device(argv[0]))
        {
            return oprom_device_version(argv[1], type);
        }
        if (arg_is_image(argv[0]))
        {
            return oprom_image_version(argv[1], type);
        }
        fwupd_error("Wrong argument %s\n", argv[0]);
        return ERROR_BAD_ARGUMENT;
    }
    else if (argc == 0)
    {
        int ret;

        if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
            device_path_found == NULL)
        {
            fwupd_error("No device or image\n");
            return EXIT_FAILURE;
        }

        ret = oprom_device_version(device_path_found, type);
        free(device_path_found);
        return ret;
    }
    fwupd_error("Wrong number of arguments\n");
    return ERROR_BAD_ARGUMENT;
}

int oprom_check_devid_enforcement(struct igsc_device_handle *handle,
                                  struct igsc_oprom_image *img)
{
    struct igsc_hw_config device_hw_config;
    int ret;
    uint32_t count;
    bool devid_enforced;
    unsigned int retries = 0;

    memset(&device_hw_config, 0, sizeof(device_hw_config));

    while ((ret = igsc_device_hw_config(handle, &device_hw_config)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }

    if (ret == IGSC_ERROR_NOT_SUPPORTED)
    {
        /* if firmware does not support hw_config command - don't check enforcement */
        return IGSC_SUCCESS;
    }
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("failed to get hw config from device, returned code %d\n", ret);
        return ret;
    }

    ret = igsc_image_oprom_code_devid_enforced(&device_hw_config, &devid_enforced);
    if (ret != IGSC_SUCCESS)
    {
       fwupd_error("Internal error: failed to check devId enforcement: %d\n", ret);
       return ret;
    }

    if (devid_enforced)
    {
        /* If devId enforcement is set - the dev ids list will be checked
         * by the match function later
         */
        return IGSC_SUCCESS;
    }

    ret = igsc_image_oprom_count_devices_typed(img, IGSC_OPROM_CODE, &count);
    if (ret != IGSC_SUCCESS)
    {
       fwupd_error("Internal error: failed to count oprom devices in the image\n");
       return ret;
    }

    if (count != 0)
    {
       fwupd_error("Oprom code devId enforcement bit is not set but the supported device list is not empty\n");
       return IGSC_ERROR_NOT_SUPPORTED;
    }
    else
    {
        return IGSC_SUCCESS;
    }
}

mockable_static
int oprom_update(const char *image_path,
                 struct igsc_device_handle *handle, struct igsc_device_info *dev_info,
                 enum igsc_oprom_type type, bool allow_downgrade)
{
    struct img *img = NULL;
    struct igsc_oprom_image *oimg = NULL;
    struct igsc_oprom_version dev_version;
    struct igsc_oprom_version img_version;
    igsc_progress_func_t progress_func = NULL;
    uint32_t img_type;
    uint8_t cmp;
    bool update = false;
    int ret;
    unsigned int retries;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        ret = EXIT_FAILURE;
        fwupd_error("Failed to read: %s\n", image_path);
        goto exit;
    }

    ret = igsc_image_oprom_init(&oimg, img->blob, img->size);
    if (ret == IGSC_ERROR_BAD_IMAGE)
    {
        fwupd_error("Invalid image format: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto exit;
    }

    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto exit;
    }

    ret = igsc_image_oprom_type(oimg, &img_type);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse oprom type in image: %s\n",
                    image_path);
        goto exit;
    }

    if ((type & img_type) == 0)
    {
        fwupd_error("Image type is %s expecting %s\n",
                    oprom_type_to_str(img_type),
                    oprom_type_to_str(type));
        ret = EXIT_FAILURE;
        goto exit;
    }

    ret = igsc_image_oprom_version(oimg, type, &img_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get oprom version from image: %s\n", image_path);
        goto exit;
    }
    print_oprom_version(type, &img_version);

    retries = 0;
    while ((ret = igsc_device_oprom_version(handle, type, &dev_version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }

    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
            fwupd_error("Permission denied: missing required credentials to access the device %s\n", dev_info->name);
        }
        else
        {
            fwupd_error("Cannot initialize device: %s\n", dev_info->name);
            print_device_fw_status(handle);
        }
        goto exit;
    }
    print_oprom_version(type, &dev_version);

    if (type == IGSC_OPROM_CODE)
    {
        /* Check devId enforcement for the case when 4ids extension exists and
         * for the case when the extension does not exist.
         * Note that in case of 2ids image and FW it will still work because the
         * 2ids FW will return that devId enforcement is disabled. */
        ret = oprom_check_devid_enforcement(handle, oimg);
        if (ret != IGSC_SUCCESS)
        {
            fwupd_error("Oprom code device enforcement failed: %d\n", ret);
            goto exit;
        }
    }

    ret = igsc_image_oprom_match_device(oimg, type, dev_info);
    if (ret == IGSC_ERROR_NOT_SUPPORTED)
    {
        fwupd_error("The image is not compatible with the device, check vid/did\n");
        goto exit;
    }
    else if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Internal error: image to device match returned %d\n", ret);
        goto exit;
    }

    cmp = igsc_oprom_version_compare(&img_version, &dev_version);
    switch (cmp)
    {
    case IGSC_VERSION_NEWER:
        update = true;
        break;
    case IGSC_VERSION_OLDER:
        /* fall through */
    case IGSC_VERSION_EQUAL:
        fwupd_msg("Installed version is newer or equal\n");
        update = allow_downgrade;
        break;
    case IGSC_VERSION_NOT_COMPATIBLE:
        fwupd_error("OPROM version is not compatible with the installed one\n");
        ret = EXIT_FAILURE;
        goto exit;
    default:
        fwupd_error("OPROM version error in comparison\n");
        ret = EXIT_FAILURE;
        goto exit;
    }

    if (!update)
    {
        fwupd_msg("In order to update run with -a | --allow-downgrade\n");
        goto exit;
    }

    if (!quiet)
    {
        if (use_progress_bar)
        {
            progress_func = progress_bar_func;
        }
        else
        {
            progress_func = progress_percentage_func;
        }
    }

    ret = igsc_device_oprom_update(handle, type, oimg, progress_func, NULL);

    /* new line after progress bar */
    if (!quiet)
    {
        printf("\n");
    }
    if (ret)
    {
        fwupd_error("OPROM update failed ret = %d\n", ret);
        print_device_fw_status(handle);
    }

    ret = igsc_device_oprom_version(handle, type, &dev_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get oprom version after update\n");
        print_device_fw_status(handle);
        goto exit;
    }
    print_oprom_version(type, &dev_version);

    /* check the new version */
    if (memcmp(&dev_version, &img_version, sizeof(struct igsc_oprom_version)))
    {
        fwupd_error("After the update oprom %s version wasn't updated on the device\n",
                    oprom_type_to_str(type));
        ret = EXIT_FAILURE;
        goto exit;
    }

exit:
    igsc_image_oprom_release(oimg);
    free(img);

    return ret;
}

static const char * const type_table[] = {
    [IGSC_IMAGE_TYPE_UNKNOWN] = "Unknown",
    [IGSC_IMAGE_TYPE_GFX_FW] = "GFX FW Update image",
    [IGSC_IMAGE_TYPE_OPROM] = "Oprom Code and Data Update image",
    [IGSC_IMAGE_TYPE_OPROM_CODE] = "Oprom Code Update image",
    [IGSC_IMAGE_TYPE_OPROM_DATA] = "Oprom Data Update image",
    [IGSC_IMAGE_TYPE_FW_DATA] = "Firmware Data update image"
};

const char *image_type_to_str(uint8_t type)
{
    if (type >= _countof(type_table))
    {
        type = IGSC_IMAGE_TYPE_UNKNOWN;
    }

    return type_table[type];
}

mockable_static
int image_type(const char *image_path)
{
    struct img *img = NULL;
    uint8_t type;
    int ret;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read: %s\n", image_path);
        return ERROR_BAD_ARGUMENT;
    }

    ret = igsc_image_get_type(img->blob, img->size, &type);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Unknown image type: %s\n", image_path);
        goto exit;
    }

    printf("Image type: %s\n", image_type_to_str(type));

exit:
    free(img);

    return ret;
}

static int do_image_type(int argc, char *argv[])
{
    const char *image_path = NULL;

    if (argc == 2)
    {
        if (arg_is_image(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No image to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            image_path = argv[0];
        }
        else
        {
            fwupd_error("Wrong argument: %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    }
    else
    {
        fwupd_error("Too few or too many arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    return image_type(image_path);
}

static int do_oprom_update(int argc, char *argv[], enum igsc_oprom_type type)
{
    bool allow_downgrade = false;
    const char *image_path = NULL;
    const char *device_path = NULL;
    struct igsc_device_info dev_info;
    struct igsc_device_handle handle;
    int ret;

    memset(&dev_info, 0, sizeof(dev_info));
    memset(&handle, 0, sizeof(handle));

    if (argc <= 0)
    {
        fwupd_error("No image to update\n");
        return ERROR_BAD_ARGUMENT;
    }

    do
    {
        if (arg_is_allow(argv[0]))
        {
            allow_downgrade = true;
            continue;
        }
        if (arg_is_quiet(argv[0]))
        {
            quiet = true;
            continue;
        }
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_image(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No image to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            image_path = argv[0];
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while (arg_next(&argc, &argv));

    if (!device_path)
    {
        if (get_first_device_info(&dev_info))
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to update\n");
            goto out;
        }

        ret = igsc_device_init_by_device_info(&handle, &dev_info);
        if (ret)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }

        igsc_device_update_device_info(&handle, &dev_info);
    }
    else
    {
        ret = igsc_device_init_by_device(&handle, device_path);
        if (ret != IGSC_SUCCESS)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }

        ret = igsc_device_get_device_info(&handle, &dev_info);
        if (ret != IGSC_SUCCESS)
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to update\n");
            goto out;
        }
    }

    if (image_path == NULL)
    {
        ret = ERROR_BAD_ARGUMENT;
        fwupd_error("No image to update\n");
        goto out;
    }

    ret = oprom_update(image_path, &handle, &dev_info, type, allow_downgrade);

out:
    igsc_device_close(&handle);
    return ret;
}

static int do_oprom_data(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "version"))
    {
        return do_oprom_version(argc, argv, IGSC_OPROM_DATA);
    }

    if (arg_is_token(sub_command, "update"))
    {
        return do_oprom_update(argc, argv, IGSC_OPROM_DATA);
    }

    if (arg_is_token(sub_command, "supported-devices"))
    {
        return do_oprom_data_supported_devices(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);

    return ERROR_BAD_ARGUMENT;
}

static int do_oprom_code(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "version"))
    {
        return do_oprom_version(argc, argv, IGSC_OPROM_CODE);
    }

    if (arg_is_token(sub_command, "update"))
    {
        return do_oprom_update(argc, argv, IGSC_OPROM_CODE);
    }

    if (arg_is_token(sub_command, "supported-devices"))
    {
        return do_oprom_code_supported_devices(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);
    return ERROR_BAD_ARGUMENT;
}

int fwdata_image_supported_devices(const char *image_path)
{
    struct img *img = NULL;
    struct igsc_fwdata_image *oimg = NULL;
    int ret;
    unsigned int i;
    uint32_t count;
    struct igsc_fwdata_device_info *devices = NULL;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        return EXIT_FAILURE;
    }

    ret = igsc_image_fwdata_init(&oimg, img->blob, img->size);
    if (ret == IGSC_ERROR_BAD_IMAGE)
    {
        fwupd_error("Invalid image format: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_fwdata_count_devices(oimg, &count);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to count supported devices on image: %s\n",
                    image_path);
        ret = EXIT_FAILURE;
        goto out;
    }
    fwupd_verbose("Found %d supported devices in image %s\n", count, image_path);

    if (count == 0)
    {
       fwupd_msg("Image %s does not include supported devices data\n", image_path);
       ret = EXIT_SUCCESS;
       goto out;
    }

    devices = calloc(count, sizeof(struct igsc_fwdata_device_info));
    if (devices == NULL) {
        fwupd_error("Out of memory\n");
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_fwdata_supported_devices(oimg, devices, &count);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get %d supported devices from image: %s\n",
                    count, image_path);
        ret = EXIT_FAILURE;
        goto out;
    }
    fwupd_verbose("Retrieved %d supported devices in image %s\n", count, image_path);

    fwupd_msg("firmware data supported devices:\n");
    for (i = 0; i < count; i++)
    {
         print_fwdata_device_info(&devices[i]);
    }

out:
    igsc_image_fwdata_release(oimg);
    free(img);
    free(devices);

    return ret;
}

mockable_static
int fwdata_image_version(const char *image_path)
{
    struct img *img = NULL;
    struct igsc_fwdata_image *oimg = NULL;
    struct igsc_fwdata_version2 fwdata_version;
    int ret;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        return EXIT_FAILURE;
    }

    ret = igsc_image_fwdata_init(&oimg, img->blob, img->size);
    if (ret == IGSC_ERROR_BAD_IMAGE)
    {
        fwupd_error("Invalid image format: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_fwdata_version2(oimg, &fwdata_version);
    if (ret == IGSC_SUCCESS)
    {
        print_img_fwdata_version(&fwdata_version);
    }
    else
    {
        fwupd_error("Failed to get firmware data version from image: %s\n", image_path);
    }

out:
    igsc_image_fwdata_release(oimg);
    free(img);

    return ret;
}


mockable_static
int fwdata_device_version(const char *device_path)
{
    struct igsc_fwdata_version2 fwdata_version;
    struct igsc_device_handle handle;
    int ret;
    unsigned int retries = 0;

    memset(&handle, 0, sizeof(handle));
    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to initialize device: %s\n", device_path);
        return ret;
    }

    memset(&fwdata_version, 0, sizeof(fwdata_version));
    while ((ret = igsc_device_fwdata_version2(&handle, &fwdata_version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
            fwupd_error("Permission denied: missing required credentials to access the device %s\n", device_path);
        }
        else
        {
            fwupd_error("Failed to get fwdata version from device: %s\n", device_path);
            print_device_fw_status(&handle);
        }
        goto exit;
    }

    print_dev_fwdata_version(&fwdata_version);

exit:
    (void)igsc_device_close(&handle);
    return ret;
}

mockable_static
int fwdata_update(const char *image_path, struct igsc_device_handle *handle,
                  struct igsc_device_info *dev_info, bool allow_downgrade)
{
    struct img *img = NULL;
    struct igsc_fwdata_image *oimg = NULL;
    struct igsc_fwdata_version2 dev_version;
    struct igsc_fwdata_version2 img_version;
    igsc_progress_func_t progress_func = NULL;
    uint8_t cmp;
    bool update = false;
    int ret;
    unsigned int retries;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        ret = EXIT_FAILURE;
        fwupd_error("Failed to read: %s\n", image_path);
        goto exit;
    }

    ret = igsc_image_fwdata_init(&oimg, img->blob, img->size);
    if (ret == IGSC_ERROR_BAD_IMAGE)
    {
        fwupd_error("Invalid image format: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto exit;
    }

    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to parse image: %s\n", image_path);
        ret = EXIT_FAILURE;
        goto exit;
    }

    ret = igsc_image_fwdata_version2(oimg, &img_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get firmware data version from image: %s\n", image_path);
        goto exit;
    }
    print_img_fwdata_version(&img_version);

    retries = 0;
    while ((ret = igsc_device_fwdata_version2(handle, &dev_version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }

    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
            fwupd_error("Permission denied: missing required credentials to access the device %s\n", dev_info->name);
        }
        else
        {
            fwupd_error("Cannot initialize device: %s\n", dev_info->name);
            print_device_fw_status(handle);
        }
        goto exit;
    }
    print_dev_fwdata_version(&dev_version);

    ret = igsc_image_fwdata_match_device(oimg, dev_info);
    if (ret == IGSC_ERROR_DEVICE_NOT_FOUND)
    {
        fwupd_error("The image is not compatible with the device\nDevice info doesn't match image device Id extension\n");
        goto exit;
    }
    else if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Internal error\n");
        goto exit;
    }

    cmp = igsc_fwdata_version_compare2(&img_version, &dev_version);
    switch (cmp)
    {
    case IGSC_FWDATA_VERSION_ACCEPT:
        update = true;
        break;
    case IGSC_FWDATA_VERSION_OLDER_VCN:
        fwupd_msg("Installed VCN version is newer\n");
        update = allow_downgrade;
        break;
    case IGSC_FWDATA_VERSION_REJECT_DIFFERENT_PROJECT:
        fwupd_error("firmware data version is not compatible with the installed one (project version)\n");
        ret = EXIT_FAILURE;
        goto exit;
    case IGSC_FWDATA_VERSION_REJECT_VCN:
        fwupd_error("firmware data version is not compatible with the installed one (VCN version)\n");
        ret = EXIT_FAILURE;
        goto exit;
    case IGSC_FWDATA_VERSION_REJECT_OEM_MANUF_DATA_VERSION:
        fwupd_error("firmware data version is not compatible with the installed one (OEM version)\n");
        ret = EXIT_FAILURE;
        goto exit;
    case IGSC_FWDATA_VERSION_REJECT_WRONG_FORMAT:
        fwupd_error("the version format is the wrong or incompatible\n");
        ret = EXIT_FAILURE;
        goto exit;
    case IGSC_FWDATA_VERSION_REJECT_ARB_SVN:
        fwupd_error("update image SVN version is smaller then the one on the device\n");
        ret = EXIT_FAILURE;
    goto exit;
    default:
        fwupd_error("firmware data version error in comparison %u\n", (uint32_t)cmp);
        ret = EXIT_FAILURE;
        goto exit;
    }

    if (!update)
    {
        fwupd_msg("In order to update run with -a | --allow-downgrade\n");
        goto exit;
    }

    if (!quiet)
    {
        if (use_progress_bar)
        {
            progress_func = progress_bar_func;
        }
        else
        {
            progress_func = progress_percentage_func;
        }
    }

    ret = igsc_device_fwdata_image_update(handle, oimg, progress_func, NULL);

    /* new line after progress bar */
    if (!quiet)
    {
        printf("\n");
    }
    if (ret)
    {
        fwupd_error("fwdata update failed ret = %d\n", ret);
        print_device_fw_status(handle);
    }

    retries = 0;
    while ((ret = igsc_device_fwdata_version2(handle, &dev_version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get firmware version after update\n");
        print_device_fw_status(handle);
        goto exit;
    }
    print_dev_fwdata_version(&dev_version);

    /* check the new version
     * If there is IGSC_FWDATA_FITB_VALID_MASK bit set in flags the update is failed.
     * Image always have zero there.
     * No need to compare FITB fields.
     */
    if (img_version.format_version != dev_version.format_version ||
        img_version.oem_manuf_data_version != dev_version.oem_manuf_data_version ||
        img_version.major_version != dev_version.major_version ||
        img_version.major_vcn != dev_version.major_vcn ||
        img_version.flags != dev_version.flags ||
        img_version.data_arb_svn != dev_version.data_arb_svn)
    {
        fwupd_error("After the update fwdata version wasn't updated on the device\n");
        ret = EXIT_FAILURE;
        goto exit;
    }

exit:
    igsc_image_fwdata_release(oimg);
    free(img);

    return ret;
}

static int do_fwdata_update(int argc, char *argv[])
{
    bool allow_downgrade = false;
    const char *image_path = NULL;
    const char *device_path = NULL;
    struct igsc_device_info dev_info;
    struct igsc_device_handle handle;
    int ret;

    memset(&dev_info, 0, sizeof(dev_info));
    memset(&handle, 0, sizeof(handle));

    if (argc <= 0)
    {
        fwupd_error("No image to update\n");
        return ERROR_BAD_ARGUMENT;
    }

    do
    {
        if (arg_is_allow(argv[0]))
        {
            allow_downgrade = true;
            continue;
        }
        if (arg_is_quiet(argv[0]))
        {
            quiet = true;
            continue;
        }
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_image(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No image to update\n");
                return ERROR_BAD_ARGUMENT;
            }
            image_path = argv[0];
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while (arg_next(&argc, &argv));

    if (!device_path)
    {
        if (get_first_device_info(&dev_info))
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to update\n");
            goto out;
        }

        ret = igsc_device_init_by_device_info(&handle, &dev_info);
        if (ret)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }
    }
    else
    {
        ret = igsc_device_init_by_device(&handle, device_path);
        if (ret != IGSC_SUCCESS)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }

        ret = igsc_device_get_device_info(&handle, &dev_info);
        if (ret != IGSC_SUCCESS)
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to update\n");
            goto out;
        }
    }

    if (image_path == NULL)
    {
        ret = ERROR_BAD_ARGUMENT;
        fwupd_error("No image to update\n");
        goto out;
    }

    ret = fwdata_update(image_path, &handle, &dev_info, allow_downgrade);

out:
    igsc_device_close(&handle);
    return ret;
}


static int do_fwdata_supported_devices(int argc, char *argv[])
{
    if (argc == 2)
    {
        if (arg_is_image(argv[0]))
        {
            return fwdata_image_supported_devices(argv[1]);
        }
        fwupd_error("Wrong argument %s\n", argv[0]);
        return ERROR_BAD_ARGUMENT;
    }

    fwupd_error("Wrong number of arguments\n");
    return ERROR_BAD_ARGUMENT;
}

static int do_fwdata_version(int argc, char *argv[])
{
    char *device_path_found = NULL;

    if (argc == 2)
    {
        if (arg_is_device(argv[0]))
        {
            return fwdata_device_version(argv[1]);
        }
        if (arg_is_image(argv[0]))
        {
            return fwdata_image_version(argv[1]);
        }
        fwupd_error("Wrong argument %s\n", argv[0]);
        return ERROR_BAD_ARGUMENT;
    }
    else if (argc == 0)
    {
        int ret;

        if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
            device_path_found == NULL)
        {
            fwupd_error("No device or image\n");
            return EXIT_FAILURE;
        }

        ret = fwdata_device_version(device_path_found);
        free(device_path_found);
        return ret;
    }
    fwupd_error("Wrong number of arguments\n");
    return ERROR_BAD_ARGUMENT;
}

static int do_firmware_data(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "version"))
    {
        return do_fwdata_version(argc, argv);
    }

    if (arg_is_token(sub_command, "update"))
    {
        return do_fwdata_update(argc, argv);
    }

    if (arg_is_token(sub_command, "supported-devices"))
    {
        return do_fwdata_supported_devices(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);

    return ERROR_BAD_ARGUMENT;
}

const char * const gfsp_pending_reset_str[] = {
    "No reset needed",
    "Need to perform a shallow reset",
    "Need to perform a deep reset",
};

#define MAX_TILES_NUM 4

mockable_static
int get_mem_err(struct igsc_device_handle *handle)
{
    int      ret;
    uint32_t i, tiles_num;
    uint8_t buf[sizeof(struct igsc_gfsp_mem_err) + MAX_TILES_NUM * sizeof(struct igsc_gfsp_tile_mem_err)];
    struct igsc_gfsp_mem_err *tiles = (struct igsc_gfsp_mem_err *) buf;
    unsigned int retries;

    /* set the number of tiles in the structure that will be passed as a buffer */
    tiles->num_of_tiles = MAX_TILES_NUM;

    retries = 0;
    /* call the igsc library routine to get number of tiles */
    while ((ret = igsc_gfsp_count_tiles(handle, &tiles_num)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to get number of tiles, returned %d\n", ret);
        return EXIT_FAILURE;
    }

    if (tiles_num > MAX_TILES_NUM)
    {
       fwupd_error("Number of tiles is too big (%u), should not be bigger than %u\n",
                   tiles_num, MAX_TILES_NUM);
    }

    retries = 0;
    /* call the igsc library routine to get memory errors */
    while ((ret = igsc_gfsp_memory_errors(handle, tiles)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to get memory errors number, returned %d\n", ret);
        print_device_fw_status(handle);
        return EXIT_FAILURE;
    }
    printf("Maximum number of tiles: %u\n", tiles->num_of_tiles);
    for (i = 0; i < tiles->num_of_tiles; i++)
        printf("tile %u: correctable memory errors: %u, uncorrectable memory errors: %u\n",
               i, tiles->errors[i].corr_err, tiles->errors[i].uncorr_err);

    return ret;
}

const char * const gfsp_ppr_mode_str[] = {
    "enabled",
    "disabled",
    "test mode",
    "auto run on next boot",
};

const char * const gfsp_ppr_applied_str[] = {
    "ppr not applied",
    "ppr applied",
    "ppr exhausted",
};

void print_mem_ppr_status(struct igsc_ppr_status *sts)
{
    printf("PPR status:\n");
    printf("Boot time memory correction pending: %u\n",
           sts->boot_time_memory_correction_pending);
    if (sizeof(gfsp_ppr_mode_str)/sizeof(char*) <= sts->ppr_mode)
        printf("PPR mode: %u\n", sts->ppr_mode);
    else
        printf("PPR mode: %s\n", gfsp_ppr_mode_str[sts->ppr_mode]);
    printf("Test run status: executed: %s\n",
           (sts->test_run_status & IGSC_PPR_STATUS_TEST_EXECUTED_MASK) ? "Test not executed" : "Test executed");
    printf("Test run status: finished successfully: %s\n",
           (sts->test_run_status & IGSC_PPR_STATUS_TEST_SUCCESS_MASK) ? "Error occurred during test execution" : "Test finished successfully");
    printf("Test run status: found hw error: %s\n",
           (sts->test_run_status & IGSC_PPR_STATUS_FOUND_HW_ERROR_MASK) ? "HW error found" : "HW error not found");
    printf("Test run status: hw error repaired: %s\n",
           (sts->test_run_status & IGSC_PPR_STATUS_HW_ERROR_REPAIRED_MASK) ? "HW error is unrepairable" : "HW error repaired or no HW error found");
    if (sizeof(gfsp_ppr_applied_str)/sizeof(char*) <= sts->ras_ppr_applied)
        printf("RAS PPR test applied: %u\n", sts->ras_ppr_applied);
    else
        printf("RAS PPR test applied: %s\n", gfsp_ppr_applied_str[sts->ras_ppr_applied]);
    printf("mbist completed: %u\n", sts->mbist_completed);
    printf("Number of PPR devices: %u\n", sts->num_devices);

    for (uint32_t i = 0; i < sts->num_devices; i++)
    {
        printf("Device[%u]:\n", i);
        printf("\t mbist test status: %u\n",
               sts->device_mbist_ppr_status[i].mbist_test_status);
        printf("\t Number of PPR fuses used by fw: %u\n",
               sts->device_mbist_ppr_status[i].num_of_ppr_fuses_used_by_fw);
        printf("\t Number of remaining PPR fuses: %u\n",
               sts->device_mbist_ppr_status[i].num_of_remaining_ppr_fuses);
    }
}

mockable_static
int get_mem_ppr_status(struct igsc_device_handle *handle)
{
    int      ret;
    uint32_t device_num = 0;
    struct igsc_ppr_status *ppr_status;
    unsigned int retries;

    retries = 0;
    /* call the igsc library routine to get number of memory ppr devices */
    while ((ret = igsc_memory_ppr_devices(handle, &device_num)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to retrieve memory ppr devices number, return code %d\n", ret);
        print_device_fw_status(handle);
        return EXIT_FAILURE;
    }

    fwupd_msg("Retrieved memory ppr devices number: %u\n", device_num);

    /* allocate ppr_status structure according to the number of ppr devices */
    ppr_status = (struct igsc_ppr_status *) malloc(sizeof(struct igsc_ppr_status) +
                                                   device_num * sizeof(struct igsc_device_mbist_ppr_status));
    if (!ppr_status)
    {
        fwupd_error("Failed to allocate memory\n");
        return EXIT_FAILURE;
    }
    /* set number of devices in the buffer structure that will be passed as parameter */
    ppr_status->num_devices = device_num;

    retries = 0;
    /* call the igsc library routine to get ppr status */
    while ((ret = igsc_memory_ppr_status(handle, ppr_status)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }

    if (ret)
    {
        fwupd_error("Failed to retrieve ppr status, return code %d\n", ret);
        print_device_fw_status(handle);
    }
    else
    {
        print_mem_ppr_status(ppr_status);
    }

    free (ppr_status);
    return ret;
}

mockable_static
int get_status_ext(struct igsc_device_handle *handle)
{
    int      ret;
    uint32_t supported_tests;
    uint32_t hw_capabilities;
    uint32_t ifr_applied;
    uint32_t prev_errors;
    uint32_t pending_reset;
    unsigned int retries = 0;

    /* call the igsc library routine to get the ifr status (extended) */
    while ((ret = igsc_ifr_get_status_ext(handle, &supported_tests, &hw_capabilities,
                                          &ifr_applied, &prev_errors, &pending_reset)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }

    if (ret)
    {
        fwupd_error("Failed to get ifr status, library return code %d\n", ret);
        print_device_fw_status(handle);
        return EXIT_FAILURE;
    }

    printf("Array and scan test supported: %u\n",
           (supported_tests & IGSC_IFR_SUPPORTED_TESTS_ARRAY_AND_SCAN) ? 1 : 0);
    printf("Memory PPR test supported: %u\n\n",
           (supported_tests & IGSC_IFR_SUPPORTED_TESTS_MEMORY_PPR) ? 1 : 0);

    if (hw_capabilities & IGSC_IRF_HW_CAPABILITY_IN_FIELD_REPAIR)
    {
        printf("Both in-field tests and in field repairs are supported\n");
    }
    else
    {
        printf("Only in-field tests are supported\n");
    }
    printf("Full EU mode switch supported: %u\n\n",
           (hw_capabilities & IGSC_IRF_HW_CAPABILITY_FULL_EU_MODE_SWITCH) ? 1 : 0);

    printf("DSS enable repair applied: %u\n",
           (ifr_applied & IGSC_IFR_REPAIRS_MASK_DSS_EN_REPAIR) ? 1 : 0);
    printf("Array repair applied: %u\n\n",
           (ifr_applied & IGSC_IFR_REPAIRS_MASK_ARRAY_REPAIR) ? 1 : 0);

    printf("DSS Engine error in an array test status packet: %u\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_DSS_ERR_ARR_STS_PKT) ? 1 : 0 );
    printf("Non DSS Engine error in an array test status packet: %u\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_NON_DSS_ERR_ARR_STS_PKT) ? 1 : 0 );
    printf("DSS Repairable repair packet in an array test: %u\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_DSS_REPAIRABLE_PKT) ? 1 : 0 );
    printf("DSS Unrepairable repair packet in an array test: %u\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_DSS_UNREPAIRABLE_PKT) ? 1 : 0 );
    printf("Non DSS Repairable repair packet in an array test: %u\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_NON_DSS_REPAIRABLE_PKT) ? 1 : 0 );
    printf("Non DSS Unrepairable repair packet in an array test: %u\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_NON_DSS_UNREPAIRABLE_PKT) ? 1 : 0 );
    printf("DSS failure in a scan test packet: %u\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_DSS_ERR_SCAN_STS_PKT) ? 1 : 0 );
    printf("Non DSS failure in a scan test packet: %u\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_NON_DSS_ERR_SCAN_STS_PKT) ? 1 : 0 );
    printf("Unexpected test failure: %u\n\n",
           (prev_errors & IGSC_IFR_PREV_ERROR_UNEXPECTED) ? 1 : 0 );

    if (sizeof(gfsp_pending_reset_str)/sizeof(char*) <= pending_reset)
        printf("Pending reset: %u\n", pending_reset);
    else
        printf("Pending reset: %s\n", gfsp_pending_reset_str[pending_reset]);

    return ret;
}

mockable_static
int get_status(struct igsc_device_handle *handle)
{
    int      ret;
    uint32_t supported_tests = 0;
    uint32_t ifr_applied = 0;
    uint8_t  tiles_num = 0;
    uint8_t  result = 0;
    unsigned int retries = 0;

    /* call the igsc library routine to get the ifr status */
    while ((ret = igsc_ifr_get_status(handle, &result, &supported_tests, &ifr_applied, &tiles_num)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret || result)
    {
        fwupd_error("Failed to get ifr status, library return code %d, command result %u\n",
                    ret, result);
        print_device_fw_status(handle);
        return EXIT_FAILURE;
    }

    printf("Number of tiles: %u\n", tiles_num);
    printf("Supported tests: scan_test: %u, array test: %u\n",
           !!(supported_tests & IGSC_IFR_SUPPORTED_TEST_SCAN),
           !!(supported_tests & IGSC_IFR_SUPPORTED_TEST_ARRAY));
    printf("Applied repairs: DSS EN repair: %u, Array repair: %u\n",
           !!(ifr_applied & IGSC_IFR_REPAIR_DSS_EN),
           !!(ifr_applied &IGSC_IFR_REPAIR_ARRAY));

    return ret;
}

const char * const array_scan_test_extended_status_str[] = {
    "Test passed successfully, no repairs needed",
    "Shallow reset already pending from previous test, aborting test",
    "Deep reset already pending from previous test, aborting test",
    "Test passed, recoverable error found, no repair needed",
    "Test passed, recoverable error found and repaired using array repairs",
    "Test passed, recoverable error found and repaired using Subslice swaps",
    "Test passed, recoverable error found and repaired using array repairs and Subslice swaps",
    "Test passed, recoverable error found and repaired using array repairs and faulty spare Subslice",
    "Test completed, unrecoverable error found, part doesn't support in field repair",
    "Test completed, unrecoverable error found, part doesn't support in field repair",
    "Test completed, unrecoverable error found, non-Subslice failure in Array test",
    "Test completed, unrecoverable error found, non-Subslice failure in Scan test",
    "Test error",
};

mockable_static
int array_scan_test(struct igsc_device_handle *handle)
{
    int      ret;
    uint32_t status;
    uint32_t extended_status;
    uint32_t pending_reset;
    uint32_t error_code;
    unsigned int retries = 0;

    /* call the igsc library routine to run array&scan tests */
    while ((ret = igsc_ifr_run_array_scan_test(handle, &status, &extended_status, &pending_reset, &error_code)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to run array and scan ifr test, library return code %d\n",
                    ret);
        print_device_fw_status(handle);
        return EXIT_FAILURE;
    }

    printf("Test execution status: %s\n",
           (status & IGSC_ARRAY_SCAN_STATUS_TEST_EXECUTION_MASK) ? "Test not executed" : "Test executed");
    printf("Test result: %s\n",
           (status & IGSC_ARRAY_SCAN_STATUS_TEST_RESULT_MASK) ? "Error occurred during test execution": "Test finished successfully");
    printf("HW error found: %s\n",
           (status & IGSC_ARRAY_SCAN_STATUS_FOUND_HW_ERROR_MASK) ? "HW error found" : "HW error not found");
    printf("HW repair status: %s\n",
           (status & IGSC_ARRAY_SCAN_STATUS_HW_REPAIR_MASK) ? "HW error will not be fully repaired" : "HW error will be fully repaired or no HW error found");
    if (sizeof(array_scan_test_extended_status_str)/sizeof(char*) <= extended_status)
        printf("Extended status: %u\n", extended_status);
    else
        printf("Extended status: %s\n", array_scan_test_extended_status_str[extended_status]);
    if (sizeof(gfsp_pending_reset_str)/sizeof(char*) <= pending_reset)
        printf("Pending reset: %u\n", pending_reset);
    else
        printf("Pending reset: %s\n", gfsp_pending_reset_str[pending_reset]);
    printf("Error code %u\n", error_code);

    return ret;
}

mockable_static
int mem_ppr_test(struct igsc_device_handle *handle)
{
    int ret;
    uint32_t status;
    uint32_t pending_reset;
    uint32_t error_code;
    unsigned int retries = 0;

    /* call the igsc library routine to run memory ppr test */
    while ((ret = igsc_ifr_run_mem_ppr_test(handle, &status, &pending_reset, &error_code)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to run ppr test, library return code %d\n", ret);
        print_device_fw_status(handle);
        return EXIT_FAILURE;
    }

    printf("Status: %u\n", status);
    if (sizeof(gfsp_pending_reset_str)/sizeof(char*) <= pending_reset)
        printf("Pending reset: %u\n", pending_reset);
    else
        printf("Pending reset: %s\n", gfsp_pending_reset_str[pending_reset]);
    printf("Error code %u\n", error_code);

    return ret;
}

mockable_static
int ifr_count_tiles(struct igsc_device_handle *handle)
{
    int ret;
    uint16_t supported_tiles;
    unsigned int retries = 0;

    /* call the igsc library routine to run ifr count tiles */
    while ((ret = igsc_ifr_count_tiles(handle, &supported_tiles)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to run ifr count tiles, library return code %d\n", ret);
        print_device_fw_status(handle);
        return EXIT_FAILURE;
    }

    printf("Number of supported tiles: %u\n", supported_tiles);

    return ret;
}

mockable_static
int ifr_version(struct igsc_device_handle *handle)
{
    int ret;
    struct igsc_ifr_bin_version version;
    unsigned int retries = 0;

    memset(&version, 0, sizeof(version));

    while ((ret = igsc_device_ifr_bin_version(handle, &version)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret != IGSC_SUCCESS)
    {
        if (ret == IGSC_ERROR_PERMISSION_DENIED)
        {
           fwupd_error("Permission denied: missing required credentials to access the device\n");
        }
        else {
            fwupd_error("Cannot retrieve IFR version from device, ret = %d\n", ret);
            print_device_fw_status(handle);
        }
        return EXIT_FAILURE;
    }

    print_ifr_bin_version(&version);

    return ret;
}

mockable_static
int ecc_config_get(struct igsc_device_handle *handle)
{
    int     ret;
    uint8_t cur_ecc_state = 0xFF;
    uint8_t pen_ecc_state = 0xFF;
    unsigned int retries = 0;

    while ((ret = igsc_ecc_config_get(handle, &cur_ecc_state, &pen_ecc_state)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to get ECC config, return code %d\n", ret);
        print_device_fw_status(handle);
    }
    else
    {
	    fwupd_msg("Current ECC State: %u\n", cur_ecc_state);
	    fwupd_msg("Pending ECC State: %u\n", pen_ecc_state);
    }
    return ret;
}

static int do_no_special_args_func(int argc, char *argv[], int (*func_ptr)(struct igsc_device_handle *))
{
    struct igsc_device_handle handle;
    int ret;
    struct igsc_device_info dev_info;

    memset(&handle, 0, sizeof(handle));

    if (argc == 2)
    {
        if (arg_is_device(argv[0]))
        {
            ret = igsc_device_init_by_device(&handle, argv[1]);
            if (ret)
            {
               ret = EXIT_FAILURE;
               fwupd_error("Cannot initialize device: %s\n", argv[1]);
               goto out;
            }
        }
        else
        {
               return EXIT_FAILURE;
        }
    }
    else if (argc != 0)
    {
        fwupd_error("Too many or wrong arguments\n");
        return ERROR_BAD_ARGUMENT;
    }
    else
    {
        /* Should be no more args */
        if (arg_next(&argc, &argv))
        {
            fwupd_error("Too many arguments\n");
            return ERROR_BAD_ARGUMENT;
        }

        if (get_first_device_info(&dev_info))
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to work with\n");
            goto out;
        }

        ret = igsc_device_init_by_device_info(&handle, &dev_info);
        if (ret)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }
    }

    ret = (*func_ptr)(&handle);

out:
    igsc_device_close(&handle);
    return ret;
}

static int do_arbsvn_commit(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, arbsvn_commit);
}

static int do_arbsvn_get_min_allowed_svn(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, arbsvn_get_min_allowed_svn);
}

static int do_oem_version(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, oem_version);
}

static int do_gfsp_get_mem_err(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, get_mem_err);
}

static int do_gfsp_get_mem_ppr_status(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, get_mem_ppr_status);
}

static int do_ifr_get_status(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, get_status);
}

static int do_ifr_get_status_ext(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, get_status_ext);
}

static int do_ifr_run_array_scan_test(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, array_scan_test);
}

static int do_ifr_run_mem_ppr_test(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, mem_ppr_test);
}

static int do_ifr_count_tiles(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, ifr_count_tiles);
}

static int do_iaf_psc_version(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, iaf_psc_version);
}

static int do_ifr_version(int argc, char *argv[])
{
    return do_no_special_args_func(argc, argv, ifr_version);
}

static void print_run_test_status(uint8_t run_status)
{
    switch (run_status)
    {
        case IFR_TEST_STATUS_SUCCESS:
            printf("Test passed successfully\n");
            break;
        case IFR_TEST_STATUS_PASSED_WITH_REPAIR:
            printf("Test passed, recoverable error found and repaired. No subslice swap needed\n");
            break;
        case IFR_TEST_STATUS_PASSED_WITH_RECOVERY:
            printf("Test passed, recoverable error found and repaired. Subslice swap needed\n");
            break;
        case IFR_TEST_STATUS_SUBSLICE_FAILURE:
            printf("Test completed, unrecoverable error found (Subslice failure and no spare Subslice available)\n");
            break;
        case IFR_TEST_STATUS_NON_SUBSLICE_FAILURE:
            printf("Test completed, unrecoverable error found (non-Subslice failure)\n");
            break;
        case IFR_TEST_STATUS_ERROR:
            printf("Test error\n");
            break;
        default:
            printf("Unknown IFR Test Run status %u\n", run_status);
    }
}

static int do_iaf_psc(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "update"))
    {
        return do_iaf_psc_update(argc, argv);
    }

    if (arg_is_token(sub_command, "version"))
    {
        return do_iaf_psc_version(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);
    return ERROR_BAD_ARGUMENT;
}

mockable_static
int run_ifr_test(struct igsc_device_handle *handle, uint8_t test_type, uint8_t tiles_mask)
{
    int ret;
    uint8_t run_status = 0;
    uint32_t error_code = 0;
    uint8_t result = 0;
    unsigned int retries = 0;

    printf("requesting to run test %u (%s) for tiles: (%u,%u)\n",
           test_type,
           (test_type == 1) ? "array" : "scan",
           !!(tiles_mask & IGSC_IFR_TILE_0),
           !!(tiles_mask & IGSC_IFR_TILE_1));

    /* call the igsc library routine to run the ifr test */
    while ((ret = igsc_ifr_run_test(handle, test_type, tiles_mask, &result, &run_status, &error_code)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret || result)
    {
        fwupd_error("Failed to run test, library return code %d Heci result %u\n",
                    ret, result);
        print_device_fw_status(handle);
        return EXIT_FAILURE;
    }

    print_run_test_status(run_status);
    printf("error_code is %u\n", error_code);
    return ret;
}

static int do_ifr_get_repair_info(int argc, char *argv[])
{
    struct igsc_device_handle handle;
    const char *device_path = NULL;
    struct igsc_device_info dev_info;
    uint16_t tile_idx = 0;
    uint16_t used_array_repair_entries; /**< Number of array repair entries used by FW */
    uint16_t available_array_repair_entries; /**< Number of available array repair entries */
    uint16_t failed_dss; /**< Number of failed DSS */
    int ret;
    unsigned int retries = 0;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    memset(&handle, 0, sizeof(handle));

    do
    {
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device was provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_tile(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No tile provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (arg_is_token(argv[0], "0"))
            {
                tile_idx = 0;
            }
            else if (arg_is_token(argv[0], "1"))
            {
                tile_idx = 1;
            }
            else
            {
                fwupd_error("Bad tile number argument\n");
                return ERROR_BAD_ARGUMENT;
            }
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while(arg_next(&argc, &argv));

    if (device_path)
    {
        ret = igsc_device_init_by_device(&handle, device_path);
        if (ret)
        {
           ret = EXIT_FAILURE;
           fwupd_error("Cannot initialize device: %s\n", device_path);
           goto out;
        }
    }
    else
    {
        if (get_first_device_info(&dev_info))
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to work with\n");
            goto out;
        }

        ret = igsc_device_init_by_device_info(&handle, &dev_info);
        if (ret)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }
    }

    printf("requesting ifr repair info for tile %u\n", tile_idx);

    /* call the igsc library routine to run the ifr test */
    while ((ret = igsc_ifr_get_tile_repair_info(&handle, tile_idx,
                                                &used_array_repair_entries,
                                                &available_array_repair_entries,
                                                &failed_dss)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }

    if (ret)
    {
       fwupd_error("Failed to run test, library return code %d\n",
                   ret);
       ret = EXIT_FAILURE;
       goto out;
    }

    printf("Number of used array repair entries: %u\n", used_array_repair_entries);
    printf("Number of available array repair entries: %u\n", available_array_repair_entries);
    printf("Number of failed DSS: %u\n", failed_dss);

out:
    igsc_device_close(&handle);
    return ret;

}

static int do_ifr_run_test(int argc, char *argv[])
{
    struct igsc_device_handle handle;
    const char *device_path = NULL;
    struct igsc_device_info dev_info;
    uint8_t  tiles_mask = 0;
    uint8_t test_type = 0;
    int ret;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    memset(&handle, 0, sizeof(handle));

    do
    {
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device was provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_tile(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No tile provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (arg_is_token(argv[0], "0"))
            {
                tiles_mask = IGSC_IFR_TILE_0;
            }
            else if (arg_is_token(argv[0], "1"))
            {
                tiles_mask = IGSC_IFR_TILE_1;
            }
            else if (arg_is_token(argv[0], "01") || arg_is_token(argv[0], "all"))
            {
                tiles_mask = IGSC_IFR_TILE_0 | IGSC_IFR_TILE_1;
            }
            else
            {
                fwupd_error("Bad tile number argument\n");
                return ERROR_BAD_ARGUMENT;
            }
        }
        else if (arg_is_test(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No test type provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (arg_is_token(argv[0], "scan"))
            {
                test_type = 0;
            }
            else if (arg_is_token(argv[0], "array"))
            {
                test_type = 1;
            }
            else
            {
                fwupd_error("Bad test type argument\n");
                return ERROR_BAD_ARGUMENT;
            }
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while(arg_next(&argc, &argv));

    if (0 == (tiles_mask & (IGSC_IFR_TILE_0 | IGSC_IFR_TILE_1)))
    {
        fwupd_error("Bad tile number argument\n");
        return ERROR_BAD_ARGUMENT;
    }

    if (device_path)
    {
        ret = igsc_device_init_by_device(&handle, device_path);
        if (ret)
        {
           ret = EXIT_FAILURE;
           fwupd_error("Cannot initialize device: %s\n", device_path);
           goto out;
        }
    }
    else
    {
        if (get_first_device_info(&dev_info))
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to work with\n");
            goto out;
        }

        ret = igsc_device_init_by_device_info(&handle, &dev_info);
        if (ret)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }
    }

    ret = run_ifr_test(&handle, test_type, tiles_mask);

out:
    igsc_device_close(&handle);
    return ret;
}

static int do_ifr(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "get-status"))
    {
        return do_ifr_get_status(argc, argv);
    }

    if (arg_is_token(sub_command, "get-status-ext"))
    {
        return do_ifr_get_status_ext(argc, argv);
    }

    if (arg_is_token(sub_command, "run-test"))
    {
        return do_ifr_run_test(argc, argv);
    }

    if (arg_is_token(sub_command, "run-array-scan-test"))
    {
        return do_ifr_run_array_scan_test(argc, argv);
    }

    if (arg_is_token(sub_command, "run-mem-ppr-test"))
    {
        return do_ifr_run_mem_ppr_test(argc, argv);
    }

    if (arg_is_token(sub_command, "get-repair-info"))
    {
        return do_ifr_get_repair_info(argc, argv);
    }

    if (arg_is_token(sub_command, "count-tiles"))
    {
        return do_ifr_count_tiles(argc, argv);
    }

    if (arg_is_token(sub_command, "version"))
    {
        return do_ifr_version(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);
    return ERROR_BAD_ARGUMENT;
}

static int do_oem(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "version"))
    {
        return do_oem_version(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);
    return ERROR_BAD_ARGUMENT;
}

static int do_arbsvn(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "commit"))
    {
        return do_arbsvn_commit(argc, argv);
    }

    if (arg_is_token(sub_command, "get-min-allowed-svn"))
    {
        return do_arbsvn_get_min_allowed_svn(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);
    return ERROR_BAD_ARGUMENT;
}

mockable_static
int do_gfsp_ecc_config_set(int argc, char *argv[])
{
    struct igsc_device_handle handle;
    const char *device_path = NULL;
    struct igsc_device_info dev_info;
    unsigned long req_ecc_state = 0xFF;
    uint8_t cur_ecc_state = 0xFF;
    uint8_t pen_ecc_state = 0xFF;
    int ret;
    unsigned int retries = 0;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    memset(&handle, 0, sizeof(handle));

    do
    {
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device was provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_ecc_config(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No ecc config value provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (arg_is_token(argv[0], "0"))
            {
                req_ecc_state = 0;
            }
            else if (arg_is_token(argv[0], "1"))
            {
                req_ecc_state = 1;
            }
            else
            {
                fwupd_error("Bad ecc config value argument '%s'\n", argv[0]);
                return ERROR_BAD_ARGUMENT;
            }
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while(arg_next(&argc, &argv));

    if (!(req_ecc_state == 0 || req_ecc_state == 1))
    {
        fwupd_error("No ecc config value\n");
        return ERROR_BAD_ARGUMENT;
    }

    if (device_path)
    {
        ret = igsc_device_init_by_device(&handle, device_path);
        if (ret)
        {
           ret = EXIT_FAILURE;
           fwupd_error("Cannot initialize device: %s\n", device_path);
           goto out;
        }
    }
    else
    {
        if (get_first_device_info(&dev_info))
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to work with\n");
            goto out;
        }

        ret = igsc_device_init_by_device_info(&handle, &dev_info);
        if (ret)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }
    }

    while ((ret = igsc_ecc_config_set(&handle, (uint8_t)req_ecc_state, &cur_ecc_state, &pen_ecc_state)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }
    if (ret)
    {
        fwupd_error("Failed to set ECC config, return code %d\n", ret);
    }
    else
    {
	    fwupd_msg("Current ECC State: %u\n", cur_ecc_state);
	    fwupd_msg("Pending ECC State: %u\n", pen_ecc_state);
    }

out:
    igsc_device_close(&handle);
    return ret;
}

static int read_from_file_to_buf(const char *p_path, uint8_t *buf, size_t buf_len, size_t *actual_size)
{
    FILE  *fp = NULL;
    long file_size;
    char err_msg[64] = {0};
    int ret = 0;

    errno = 0;

    if (fopen_s(&fp, p_path, "rb") != 0 || fp == NULL)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to open file %s : %s\n", p_path, err_msg);
        ret = -1;
        goto exit;
    }

    if (fseek(fp, 0L, SEEK_END) != 0)
    {
        fwupd_verbose("Failed to get file size %s : %s\n",
                      p_path, err_msg);
        ret = -1;
        goto exit;
    }

    file_size = ftell(fp);
    if (file_size < 0)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to get file size %s : %s\n",
                      p_path, err_msg);
        ret = -1;
        goto exit;
    }

    if (file_size == 0)
    {
        *actual_size = 0;
        ret = 0;
        goto exit;
    }

    if ((size_t)file_size > buf_len)
    {
        fwupd_verbose("file size (%ld) too large\n", file_size);
        ret = -1;
        goto exit;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to reset file position %s : %s\n",
                      p_path, err_msg);
        ret = -1;
        goto exit;
    }

    if (fread(buf, 1, (size_t)file_size, fp) != (size_t)file_size)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to read file %s : %s\n",
                      p_path, err_msg);
        ret = -1;
        goto exit;
    }
    *actual_size = (uint32_t)file_size;

exit:
    if (fp)
    {
        fclose(fp);
    }

    return ret;
}


static int write_to_file_from_buf(const char *p_path, uint8_t *buf, size_t buf_len)
{
    FILE  *fp = NULL;
    char err_msg[64] = {0};
    errno = 0;

    if (fopen_s(&fp, p_path, "wb") != 0 || fp == NULL)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to open file %s : %s\n", p_path, err_msg);
        goto exit;
    }

    if (fwrite(buf, 1, buf_len, fp) != buf_len)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to read file %s : %s\n",
                      p_path, err_msg);
        goto exit;
    }

    fclose(fp);

    return 0;

exit:
    if (fp)
    {
        fclose(fp);
    }

    return -1;
}


#define MAX_BUF_SIZE 2048

mockable_static
int do_gfsp_generic_cmd(int argc, char *argv[])
{
    struct igsc_device_handle handle;
    const char *device_path = NULL;
    struct igsc_device_info dev_info;
    uint32_t cmd = 0;
    char *infile = NULL, *outfile = NULL;
    uint8_t in_buf[MAX_BUF_SIZE], out_buf[MAX_BUF_SIZE];
    size_t in_buf_size = 0;
    int ret;
    size_t actual_received_size = 0;
    unsigned int retries = 0;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    memset(&handle, 0, sizeof(handle));

    do
    {
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device was provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_cmd(argv[0]))
        {
            if (infile)
            {
                fwupd_error("The in-file argument appears twice\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No fgsp command value provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            cmd = (uint32_t)atol(argv[0]);
            if (!cmd)
            {
                fwupd_error("Bad gfsp command value argument '%s'\n", argv[0]);
                return ERROR_BAD_ARGUMENT;
            }
        }
        else if (arg_is_in(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No in-file name provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            infile = argv[0];
        }
        else if (arg_is_out(argv[0]))
        {
            if (outfile)
            {
                fwupd_error("The out-file argument appears twice\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No out-file name provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            outfile = argv[0];
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while(arg_next(&argc, &argv));

    if (cmd == 0 || !infile || !outfile)
    {
        fwupd_error("Not enough arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    if (device_path)
    {
        ret = igsc_device_init_by_device(&handle, device_path);
        if (ret)
        {
           ret = EXIT_FAILURE;
           fwupd_error("Cannot initialize device: %s\n", device_path);
           goto out;
        }
    }
    else
    {
        if (get_first_device_info(&dev_info))
        {
            ret = EXIT_FAILURE;
            fwupd_error("No device to work with\n");
            goto out;
        }

        ret = igsc_device_init_by_device_info(&handle, &dev_info);
        if (ret)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Cannot initialize device: %s\n", dev_info.name);
            goto out;
        }
    }

    if (read_from_file_to_buf(infile, in_buf, sizeof(in_buf), &in_buf_size) != 0)
    {
        printf("Failed to read file : %s, using empty in buffer\n", infile);
        in_buf_size = 0;
    }
    printf("Sending %zu bytes of input data by gfsp generic api\n", in_buf_size);
    if (in_buf_size)
    {
        while ((ret = igsc_gfsp_heci_cmd(&handle, cmd, in_buf, in_buf_size,
                                         out_buf, sizeof(out_buf),
                                         &actual_received_size)) == IGSC_ERROR_BUSY)
        {
            gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
            if (++retries >= MAX_CONNECT_RETRIES)
                break;
        }
    }
    else
    {
        while ((ret = igsc_gfsp_heci_cmd(&handle, cmd, NULL, 0,
                                         out_buf, sizeof(out_buf),
                                         &actual_received_size)) == IGSC_ERROR_BUSY)
        {
            gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
            if (++retries >= MAX_CONNECT_RETRIES)
                break;
        }
    }
    printf("Received %zu bytes of data\n", actual_received_size);
    if (ret)
    {
        fwupd_error("gfsp command failed, return code %d, bytes received %zu\n",
                     ret, actual_received_size);
    }
    if (ret == 0 || ret == IGSC_ERROR_BUFFER_TOO_SMALL)
    {
        /* copy data to the out_buf */
        if (write_to_file_from_buf(outfile, out_buf, actual_received_size) != 0)
        {
            ret = EXIT_FAILURE;
            fwupd_error("Failed to write file : %s\n", outfile);
            goto out;
        }
        printf("Wrote %zu bytes to %s\n", actual_received_size, outfile);
    }
    else
    {
        fwupd_error("Wrote nothing to %s\n", outfile);
    }

out:
    igsc_device_close(&handle);
    return ret;
}

void parse_late_binding_status(uint32_t status)
{
    printf("Late binding command returned 0x%x ", status);
    switch (status)
    {
    case CSC_LATE_BINDING_STATUS_SUCCESS:
        printf("(Success)\n");
        break;
    case CSC_LATE_BINDING_STATUS_4ID_MISMATCH:
        printf("(4Id Mismatch)\n");
        break;
    case CSC_LATE_BINDING_STATUS_ARB_FAILURE:
        printf("(ARB Failure)\n");
        break;
    case CSC_LATE_BINDING_STATUS_GENERAL_ERROR:
        printf("(General Error)\n");
        break;
    case CSC_LATE_BINDING_STATUS_INVALID_PARAMS:
        printf("(Invalid Params)\n");
        break;
    case CSC_LATE_BINDING_STATUS_INVALID_SIGNATURE:
        printf("(Invelid Signature)\n");
        break;
    case CSC_LATE_BINDING_STATUS_INVALID_PAYLOAD:
        printf("(Invalid Payload)\n");
        break;
    case CSC_LATE_BINDING_STATUS_TIMEOUT:
        printf("(Timeout)\n");
        break;
    default:
        printf("(Unknown error)\n");
        break;
    }
}

#define MAX_PAYLOAD_SIZE (1024 * 4)

mockable_static
int late_binding(const char *device_path, const char *payload_path, uint32_t type, uint32_t flags)
{
    struct igsc_device_handle handle;
    char *device_path_found = NULL;
    int ret;
    size_t payload_size = 0;
    uint8_t payload[MAX_PAYLOAD_SIZE];
    uint32_t status;
    unsigned int retries = 0;

    memset(&handle, 0, sizeof(handle));

    if (!device_path)
    {
        if (get_first_device(&device_path_found) != IGSC_SUCCESS ||
            device_path_found == NULL)
        {
            fwupd_error("No device to update\n");
            return EXIT_FAILURE;
        }
        device_path = device_path_found;
    }

    if (read_from_file_to_buf(payload_path, payload, sizeof(payload), &payload_size) != 0)
    {
        fwupd_error("Failed to read file : %s\n", payload_path);
        ret = EXIT_FAILURE;
        goto exit;
    }

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret)
    {
        fwupd_error("Cannot initialize device: %s\n", device_path);
        goto exit;
    }

    while ((ret = igsc_device_update_late_binding_config(&handle, type, flags,
                                                         payload, payload_size,
                                                         &status)) == IGSC_ERROR_BUSY)
    {
        gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
        if (++retries >= MAX_CONNECT_RETRIES)
            break;
    }

    if (ret)
    {
        fwupd_error("Failed to send late binding command: %d\n", ret);
        goto exit;
    }
    parse_late_binding_status(status);

exit:
    (void)igsc_device_close(&handle);

    free(device_path_found);
    return ret;

}

static int do_late_binding(int argc, char *argv[])
{
    const char *device_path = NULL;
    const char *payload_path = NULL;
    uint32_t flags = 0;
    bool flags_set = false;
    uint32_t type = 0;
    bool type_set = false;

    if (argc <= 0)
    {
        fwupd_error("No arguments provided\n");
        return ERROR_BAD_ARGUMENT;
    }

    do
    {
        if (arg_is_device(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No device to send the command to\n");
                return ERROR_BAD_ARGUMENT;
            }
            device_path = argv[0];
        }
        else if (arg_is_payload(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No payload file to send\n");
                return ERROR_BAD_ARGUMENT;
            }
            payload_path = argv[0];
        }
        else if (arg_is_flags(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No flags argument provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            flags = (uint32_t)strtol(argv[0], NULL, 16);
            flags_set = true;
        }
        else if (arg_is_type(argv[0]))
        {
            if (!arg_next(&argc, &argv))
            {
                fwupd_error("No payload type argument provided\n");
                return ERROR_BAD_ARGUMENT;
            }
            if (arg_is_vr_config(argv[0]))
            {
                type = CSC_LATE_BINDING_TYPE_VR_CONFIG;
            }
            else if (arg_is_fan_table(argv[0]))
            {
                type = CSC_LATE_BINDING_TYPE_FAN_TABLE;
            }
            else
            {
                fwupd_error("Bad payload type argument %s\n", argv[0]);
                return ERROR_BAD_ARGUMENT;
            }
            type_set = true;
        }
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while(arg_next(&argc, &argv));

    if (payload_path && flags_set && type_set)
    {
        return late_binding(device_path, payload_path, type, flags);
    }

    fwupd_error("No payload file or payload type or flags provided\n");
    return ERROR_BAD_ARGUMENT;
}

static int do_gfsp(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        fwupd_error("Missing arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    sub_command = argv[0];

    arg_next(&argc, &argv);

    if (arg_is_token(sub_command, "get-mem-err"))
    {
        return do_gfsp_get_mem_err(argc, argv);
    }
    if (arg_is_token(sub_command, "get-mem-ppr-status"))
    {
        return do_gfsp_get_mem_ppr_status(argc, argv);
    }
    if (arg_is_token(sub_command, "set-ecc-config"))
    {
        return do_gfsp_ecc_config_set(argc, argv);
    }
    if (arg_is_token(sub_command, "get-ecc-config"))
    {
        return do_no_special_args_func(argc, argv, ecc_config_get);
    }
    if (arg_is_token(sub_command, "get-health-ind"))
    {
        return do_no_special_args_func(argc, argv, get_health_indicator);
    }
    if (arg_is_token(sub_command, "generic"))
    {
        return do_gfsp_generic_cmd(argc, argv);
    }

    fwupd_error("Wrong argument %s\n", sub_command);
    return ERROR_BAD_ARGUMENT;
}

static int do_list_devices(int argc, char *argv[])
{
    struct igsc_device_iterator *iter;
    struct igsc_device_info info;
    int ret;
    struct igsc_device_handle handle;
    struct igsc_fw_version fw_version;
    struct igsc_oprom_version oprom_version;
    bool do_info = false;
    unsigned int ndevices = 0;
    unsigned int retries;

    memset(&handle, 0, sizeof(handle));
    memset(&fw_version, 0, sizeof(fw_version));
    memset(&oprom_version, 0, sizeof(oprom_version));

    if (argc >= 1)
    {
        if (arg_is_info(argv[0]))
        {
            do_info = true;
        }
        else
        {
            fwupd_error("Wrong argument: %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    }

    /* Should be no more args */
    if (arg_next(&argc, &argv))
    {
        fwupd_verbose("Too many arguments\n");
        return ERROR_BAD_ARGUMENT;
    }

    ret = igsc_device_iterator_create(&iter);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot create device iterator %d\n", ret);
        return EXIT_FAILURE;
    }

    info.name[0] = '\0';
    while ((ret = igsc_device_iterator_next(iter, &info)) == IGSC_SUCCESS)
    {

        ret = igsc_device_init_by_device_info(&handle, &info);
        if (ret != IGSC_SUCCESS)
        {
            /* make sure we have a printable name */
            info.name[0] = '\0';
            continue;
        }

        igsc_device_update_device_info(&handle, &info);

        ndevices++;

        printf("Device [%d] '%s': %04hx:%04hx %04hx:%04hx %04hu:%02x:%02x.%02x\n",
               ndevices,
               info.name,
               info.vendor_id, info.device_id,
               info.subsys_vendor_id, info.subsys_device_id,
               info.domain, info.bus, info.dev, info.func);

        if (do_info)
        {
            retries = 0;
            while ((ret = igsc_device_fw_version(&handle, &fw_version)) == IGSC_ERROR_BUSY)
            {
               gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
               if (++retries >= MAX_CONNECT_RETRIES)
                  break;
            }
            if (ret == IGSC_SUCCESS)
            {
                print_fw_version("", &fw_version);
            }
            retries = 0;
            while ((ret = igsc_device_oprom_version(&handle, IGSC_OPROM_CODE, &oprom_version)) == IGSC_ERROR_BUSY)
            {
               gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
               if (++retries >= MAX_CONNECT_RETRIES)
                  break;
            }
            if (ret == IGSC_SUCCESS)
            {
                print_oprom_code_version(&oprom_version);
            }
            retries = 0;
            while ((ret = igsc_device_oprom_version(&handle, IGSC_OPROM_DATA, &oprom_version))  == IGSC_ERROR_BUSY)
            {
               gsc_msleep(CONNECT_RETRIES_SLEEP_MSEC);
               if (++retries >= MAX_CONNECT_RETRIES)
                  break;
            }
            if (ret == IGSC_SUCCESS)
            {
                print_oprom_data_version(&oprom_version);
            }
        }
        /* make sure we have a printable name */
        info.name[0] = '\0';
        (void)igsc_device_close(&handle);
    }
    if (ret == IGSC_ERROR_DEVICE_NOT_FOUND)
    {
        ret = EXIT_SUCCESS;
    }
    else
    {
        fwupd_error("Failure in the device iterator: %d\n", ret);
    }
    igsc_device_iterator_destroy(iter);

    if (ndevices == 0)
    {
        fwupd_msg("No device found\n");
    }

    return ret;
}

static const struct gsc_op g_ops[] = {
    {
        .name  = "fw",
        .op    = do_firmware,
        .usage = {"update [options] [--device <dev>] --image  <image>",
                  "version [--device <dev>] | --image <file> ",
                  "status <index> [--device <dev>]",
                  "hwconfig [--check] [--device <dev> | --image  <image>]",
                   NULL},
        .help  = "Update firmware partition\n"
                 "Retrieve version from the devices or the supplied image\n"
                 "Retrieve firmware status register values from device\n"
                 "\nOPTIONS:\n\n"
                 "    -a | --allow-downgrade\n"
                 "            allow downgrade or override the same version\n"
                 "    -d | --device <device>\n"
                 "            device to be updated\n"
                 "    -i | --image <image file>\n"
                 "            supplied image\n"
                 "    -c | --check\n"
                 "            check whether firmware is compatible with the device\n"
                 "    -f | --force\n"
                 "            force fw update\n",

    },
    {
        .name  = "iaf",
        .op    = do_iaf_psc,
        .usage = {"update [options] [--device <dev>] --image  <image>",
                  "version [--device <dev>]",
                   NULL},
        .help  = "Update Intel Accelerator Fabric configuration data on the devices by the supplied image\n"
                 "or retrieve psc version from the device\n"
                 "\nOPTIONS:\n\n"
                 "    -d | --device <device>\n"
                 "            device to be updated\n"
                 "    -i | --image <image file>\n"
                 "            supplied image\n",
    },
    {
        .name  = "oprom-data",
        .op    = do_oprom_data,
        .usage = {"update [options] [--device <dev>] --image  <image>",
                  "version [--device <dev>] | --image <file>",
                  "supported-devices --image <file>",
                  NULL},
        .help  = "Update oprom data partition\n"
                 "or retrieve version from the devices or the supplied image\n"
                 "or retrieve list of supported devices from the supplied image\n"
                 "\nOPTIONS:\n\n"
                 "    -a | --allow-downgrade\n"
                 "            allow downgrade or override the same version\n"
                 "    -d | --device <device>\n"
                 "            device to be updated\n"
                 "    -i | --image <image file>\n"
                 "            supplied image\n",
    },
    {
        .name  = "oprom-code",
        .op    = do_oprom_code,
        .usage = {"update [options] [--device <dev>] --image <image>",
                  "version [--device <dev>] | --image <file>",
                  "supported-devices --image <file>",
                  NULL},
        .help  = "Update oprom code partition\n"
                 "or retrieve version from the devices or the supplied image\n"
                 "or retrieve list of supported devices from the supplied image\n"
                 "\nOPTIONS:\n\n"
                 "    -a | --allow-downgrade\n"
                 "            allow downgrade or override the same version\n"
                 "    -d | --device <device>\n"
                 "            device to be updated\n"
                 "    -i | --image <image file>\n"
                 "            supplied image\n",
    },
    {
        .name  = "fw-data",
        .op    = do_firmware_data,
        .usage = {"update [options] [--device <dev>] --image <image>",
                  "version [--device <dev>] | --image <file>",
                  "supported-devices --image <file>",
                  NULL},
        .help  = "Update firmware data partition\n"
                 "or retrieve version from the device or the supplied image\n"
                 "or retrieve list of supported devices from the supplied image\n"
                 "\nOPTIONS:\n\n"
                 "    -a | --allow-downgrade\n"
                 "            allow downgrade or override the same version\n"
                 "    -d | --device <device>\n"
                 "            device to be updated\n"
                 "    -i | --image <image file>\n"
                 "            supplied image\n",
    },
    {
        .name  = "list-devices",
        .op    = do_list_devices,
        .usage = {"[--info]", NULL, NULL},
        .help  = "List devices supporting firmware or oprom update\n"
                 "OPTIONS:\n\n"
                 "    --info\n"
                 "         display information for each device\n",
    },
    {
        .name  = "image-type",
        .op    = do_image_type,
        .usage = {"--image <image>", NULL, NULL},
        .help  = "Determine the type of supplied image\n"
                 "OPTIONS:\n\n"
                 "    -i | --image <image file>\n"
                 "            supplied image\n",
    },
    {
        .name  = "ifr",
        .op    = do_ifr,
        .usage = {"get-status [--device <dev>]",
                  "run-test [--device <dev>] --tile <tile> --test <test>",
                  "run-array-scan-test [--device <dev>]",
                  "run-mem-ppr-test [--device <dev>]",
                  "get-status-ext [--device <dev>]",
                  "count-tiles [--device <dev>]",
                  "get-repair-info [--device <dev>] --tile <tile>",
                  "version [--device <dev>]",
                  NULL},
        .help  = "Get IFR status or run IFR test or run memory PPR test\n"
                 "or count tiles on the device or retrieve repair info on the device\n"
                 "or retrieve ifr version from the device\n"
                 "\nOPTIONS:\n\n"
                 "    -d | --device <device>\n"
                 "            device to communicate with\n"
                 "    -t | --tile <[0|1|01|all]>\n"
                 "            specify a tile to run test on\n"
                 "    -r | --test <[scan|array]>\n"
                 "            specify the test to run\n"
    },
    {
        .name  = "gfsp",
        .op    = do_gfsp,
        .usage = {"get-mem-err [--device <dev>]",
                  "get-mem-ppr-status [--device <dev>]",
                  "set-ecc-config [--device <dev>] --ecc-config <config>",
                  "get-ecc-config [--device <dev>]",
                  "get-health-ind [--device <dev>]",
                  "generic --cmd <id> --in <infile> --out <outfile> [--device <dev>]",
                  NULL},
        .help  = "Get number of memory errors for each tile\n"
                 "Get memory PPR status\n"
                 "Set ECC configuration\n"
                 "Get ECC configuration\n"
                 "Get memory health indicator\n"
                 "\nOPTIONS:\n\n"
                 "    -d | --device <device>\n"
                 "            device to communicate with\n"
                 "    -e | --ecc-config <[0|1]>\n"
                 "           0 - Disable 1 - Enable \n"
    },
    {
        .name  = "late-binding",
        .op    = do_late_binding,
        .usage = {"--payload <payload-file> --type <[fan-table|vr-config]> "
                                "--flags <flags-hex-value> [--device <dev>]",
                   NULL},
        .help  = "Sends late binding command\n"
                 "\nOPTIONS:\n\n"
                 "    -d | --device <device>\n"
                 "            device to be updated\n"
                 "    -p | --payload <payload-file>\n"
                 "            path to file containing the payload fdata to be send\n"
                 "    -t | --type <[fan-table|vr-config]>\n"
                 "            payload type\n"
                 "    -f | --flags <flags-hex-value>\n"
                 "            flags to be sent\n"
    },
    {
        .name  = "oem",
        .op    = do_oem,
        .usage = {"version [--device <dev>]",
                   NULL},
        .help  = "Retrieve OEM version from the devices\n"
                 "\nOPTIONS:\n\n"
                 "    -d | --device <device>\n"
                 "            device to retrieve OEM version from\n"
    },
    {
        .name  = "arbsvn",
        .op    = do_arbsvn,
        .usage = {"commit [--device <dev>]",
                  "get-min-allowed-svn [--device <dev>]",
                   NULL},
        .help  = "Commit ARB SVN\n"
                 "Retrieves minimal allowed ARB SVN\n"
                 "\nOPTIONS:\n\n"
                 "    -d | --device <device>\n"
                 "            device to communicate with\n"
    },

    {
        .name  = NULL,
    }
};

static void __op_usage(const char *exe_name, const struct gsc_op *op, bool indent)
{
    unsigned int j;

    for (j = 0; op->usage[j]; j++)
    {
        printf("%s%s %s %s\n", indent ? "    " : "", exe_name, op->name, op->usage[j]);
    }
}

static void op_usage(const char *exe_name, const struct gsc_op *op)
{
        __op_usage(exe_name, op, true);
}

static void op_help(const char *exe_name, const struct gsc_op *op)
{
    printf("\n");
    __op_usage(exe_name, op, false);
    printf("\n%s\n", op->help);
}

#ifndef IGSC_VERSION
#error IGSC_VERSION not defiled
#endif

static const char igsc_version[] = IGSC_VERSION;

static void print_version(const char *exe_name)
{
    printf("%s version %s\n", exe_name, igsc_version);
}

/* FIXME: currently same as usage */
static void help(const char *exe_name)
{
    unsigned int i;

    printf("Usage: %s [-v] <command> <args>\n\n", exe_name);
    for (i = 0; g_ops[i].name; i++)
    {
        op_usage(exe_name, &g_ops[i]);
        printf("\n");
    }

    printf("\n");
    printf("    %s -V/--version: display version\n", exe_name);
    printf("    %s -v/--verbose: runs in verbose mode\n", exe_name);
    printf("    %s -t/--trace: runs in trace mode\n", exe_name);
    printf("    %s -q/--quiet: runs in quiet mode\n", exe_name);
    printf("    %s help : shows this help\n", exe_name);
    printf("    %s help <command>: shows detailed help\n", exe_name);
}

static void usage(const char *exe_name)
{
    unsigned int i;

    printf("Usage: %s [-v] <command> <args>\n\n", exe_name);
    for (i = 0; g_ops[i].name; i++)
    {
        op_usage(exe_name, &g_ops[i]);
        printf("\n");
    }

    printf("\n");
    printf("    %s -V/--version: display version\n", exe_name);
    printf("    %s -v/--verbose: runs in verbose mode\n", exe_name);
    printf("    %s -t/--trace: runs in trace mode\n", exe_name);
    printf("    %s -q/--quiet: runs in quiet mode\n", exe_name);
    printf("    %s help : shows this help\n", exe_name);
    printf("    %s help <command>: shows detailed help\n", exe_name);
}

static bool arg_is_help(const char *arg)
{
    return !strcmp(arg, "help") ||
           !strcmp(arg, "-h")   ||
           !strcmp(arg, "--help");
}

static bool arg_is_verbose(const char *arg)
{
    return !strcmp(arg, "-v") ||
           !strcmp(arg, "--verbose");
}

static bool arg_is_trace(const char *arg)
{
    return !strcmp(arg, "-t") ||
           !strcmp(arg, "--trace");
}

static bool arg_is_version(const char *arg)
{
    return arg_is_token(arg, "-V") ||
           arg_is_token(arg, "--version");
}

static int args_parse(const char *exe_name, int *argc, char **argv[],
                      const struct gsc_op **op, bool *display_help)
{
    unsigned int i;
    const struct gsc_op *__op = NULL;

    if (exe_name == NULL)
    {
        return EXIT_FAILURE;
    }

    *display_help = false;

    if (*argc == 0)
    {
        usage(exe_name);
        return EXIT_FAILURE;
    }

    if (arg_is_version(*argv[0]))
    {
        print_version(exe_name);
        return EXIT_SUCCESS;
    }

    if (arg_is_help(*argv[0]))
    {
        *display_help = true;
        if (!arg_next(argc, argv))
        {
            help(exe_name);
            goto out;
        }
    }

    if (arg_is_verbose(*argv[0]))
    {
        if (!arg_next(argc, argv))
        {
            usage(exe_name);
            return EXIT_FAILURE;
        }
        verbose = true;
        /* set log level to DEBUG in the library */
        igsc_set_log_level(IGSC_LOG_LEVEL_DEBUG);
    }

    if (arg_is_trace(*argv[0]))
    {
        if (!arg_next(argc, argv))
        {
            usage(exe_name);
            return EXIT_FAILURE;
        }
        verbose = true;
        /* set log level to TRACE in the library */
        igsc_set_log_level(IGSC_LOG_LEVEL_TRACE);
    }

    if (arg_is_quiet(*argv[0]))
    {
        if (!arg_next(argc, argv))
        {
            usage(exe_name);
            return EXIT_FAILURE;
        }
        quiet = true;
    }

    for (i = 0; g_ops[i].name; i++)
    {
        if (arg_is_token(*argv[0], g_ops[i].name))
        {
            __op = &g_ops[i];
            arg_next(argc, argv);
            break;
        }
    }

    if (__op == NULL)
    {
        usage(exe_name);
        return EXIT_FAILURE;
    }

    if (*display_help || (*argc > 0 && arg_is_help(*argv[0])))
    {
        *display_help = true;
        op_help(exe_name, __op);
        arg_next(argc, argv);
        __op = NULL;
    }

    *op = __op;

out:
    return EXIT_SUCCESS;
}

#ifdef __linux__
char *prog_name(const char *exe_path)
{
    const char *p = NULL;

    p = strrchr(exe_path, '/');
    if (p == NULL)
    {
        p = exe_path;
    }
    else
    {
        p++;
    }

    return igsc_strdup(p);
}
#else
char *prog_name(const char *exe_path)
{
    errno_t ret;
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    char *str = NULL;
    size_t str_len = 0;

   ret = _splitpath_s(exe_path, NULL, 0, NULL, 0,
                      fname, sizeof(fname), ext, sizeof(ext));
   if (ret)
   {
       return NULL;
   }

   str_len = strlen(fname) + strlen(ext) + 2;
   str = calloc(1, str_len);
   if (str == NULL)
   {
       return NULL;
   }
   strcat_s(str, str_len, fname);
   strcat_s(str, str_len, ext);

   return str;
}
#endif

int main(int argc, char* argv[])
{
    char *exe_name = prog_name(argv[0]);
    const struct gsc_op *op = NULL;
    bool display_help = false;
    int ret;

    arg_next(&argc, &argv);

    ret = args_parse(exe_name, &argc, &argv, &op, &display_help);
    if (ret != EXIT_SUCCESS || op == NULL)
    {
        goto out;
    }

    if (display_help)
    {
        goto out;
    }

    ret = op->op(argc, argv);
    if (ret == ERROR_BAD_ARGUMENT)
    {
        op_help(exe_name, op);
    }

out:
    free(exe_name);
    return (ret) ? EXIT_FAILURE : EXIT_SUCCESS;
}
