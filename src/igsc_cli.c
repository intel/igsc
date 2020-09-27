/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
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

#include "msvc/config.h"

#include "igsc_lib.h"

bool verbose = false;
bool quiet = false;
bool use_progress_bar = false;

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

#ifdef UNIT_TESTING
#define  mockable_static __attribute__((weak))
#else
#define  mockable_static static
#endif


#define MAX_UPDATE_IMAGE_SIZE (8*1024*1024)

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
    if (strerror_s(buf, buflen, errnum) != 0)
    {
         strncpy_s(buf, buflen, "Unknown error", buflen - 1);
         buf[buflen - 1] = '\0';
    }
}
#endif /* __linux__ */

static void print_fw_version(const struct igsc_fw_version *fw_version)
{
    printf("FW Version: %c%c%c%c->%d->%d\n",
           fw_version->project[0],
           fw_version->project[1],
           fw_version->project[2],
           fw_version->project[3],
           fw_version->hotfix,
           fw_version->build);
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

static void print_device_info(struct igsc_oprom_device_info *info)
{
    printf("Vendor Id: %04X Device Id: %04X\n",
           info->subsys_vendor_id, info->subsys_device_id);
}

static inline void print_oprom_code_version(const struct igsc_oprom_version *oprom_version)
{
    print_oprom_version(IGSC_OPROM_CODE, oprom_version);
}

static inline void print_oprom_data_version(const struct igsc_oprom_version *oprom_version)
{
    print_oprom_version(IGSC_OPROM_DATA, oprom_version);
}

static struct img *image_read_from_file(const char *p_path)
{
    FILE  *fp = NULL;
    struct img *img = NULL;
    long file_size;
    char err_msg[64] = {0};

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

static bool arg_is_info(const char *arg)
{
    return arg_is_token(arg, "-i") ||
           arg_is_token(arg, "--info");
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
    const char *usage[4]; /* up to 3 subcommands*/
    const char  *help;  /* help */
};

mockable_static
int firmware_update(const char *device_path,
                    const char *image_path,
                    bool allow_downgrade)
{
    struct img *img = NULL;
    struct igsc_device_handle handle;
    struct igsc_fw_version device_fw_version;
    struct igsc_fw_version image_fw_version;
    char *device_path_found = NULL;
    igsc_progress_func_t progress_func = NULL;
    int ret;
    uint8_t cmp;

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

    print_fw_version(&image_fw_version);

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret)
    {
        fwupd_error("Cannot initialize device: %s\n", device_path);
        goto exit;
    }

    memset(&device_fw_version, 0, sizeof(device_fw_version));
    ret = igsc_device_fw_version(&handle, &device_fw_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot retrieve firmware version from device: %s\n", device_path);
        goto exit;
    }
    print_fw_version(&device_fw_version);

    cmp = igsc_fw_version_compare(&image_fw_version,
                                             &device_fw_version);
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

    ret = igsc_device_fw_update(&handle, img->blob, img->size,
                                progress_func, NULL);

    /* new line after progress bar */
    if (!quiet)
    {
        printf("\n");
    }
    if (ret)
    {
        fwupd_error("Update process failed\n");
    }

    ret = igsc_device_fw_version(&handle, &device_fw_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot retrieve firmware version from device: %s\n", device_path);
        goto exit;
    }
    print_fw_version(&device_fw_version);

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

    memset(&handle, 0, sizeof(handle));
    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot initialize device: %s\n", device_path);
        goto exit;
    }

    memset(&fw_version, 0, sizeof(fw_version));
    ret = igsc_device_fw_version(&handle, &fw_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot retrieve firmware version from device: %s\n", device_path);
        goto exit;
    }

    print_fw_version(&fw_version);

exit:
    (void)igsc_device_close(&handle);
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
    print_fw_version(&fw_version);

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

static int do_firmware_update(int argc, char *argv[])
{
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
        else
        {
            fwupd_error("Wrong argument %s\n", argv[0]);
            return ERROR_BAD_ARGUMENT;
        }
    } while(arg_next(&argc, &argv));

    if (image_path)
    {
        return firmware_update(device_path, image_path, allow_downgrade);
    }

    fwupd_error("No image to update\n");
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

    if (arg_is_token(sub_command, "update"))
    {
        return do_firmware_update(argc, argv);
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

    memset(&handle, 0, sizeof(handle));
    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to initialize device: %s\n", device_path);
        return ret;
    }

    memset(&oprom_version, 0, sizeof(oprom_version));
    ret = igsc_device_oprom_version(&handle, igsc_oprom_type, &oprom_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get oprom version from device: %s\n",
                    device_path);
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
int oprom_data_image_supported_devices(const char *image_path)
{
    struct img *img = NULL;
    struct igsc_oprom_image *oimg = NULL;
    uint32_t img_type;
    int ret;
    unsigned int i;
    uint32_t count;
    struct igsc_oprom_device_info *devices = NULL;

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

    ret = igsc_image_oprom_count_devices(oimg, &count);
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

    devices = calloc(count, sizeof(struct igsc_oprom_device_info));
    if (devices == NULL) {
        fwupd_error("Out of memory\n");
        ret = EXIT_FAILURE;
        goto out;
    }

    ret = igsc_image_oprom_supported_devices(oimg, devices, &count);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get %d supported devices from image: %s\n",
                    count, image_path);
        ret = EXIT_FAILURE;
        goto out;
    }
    fwupd_verbose("Retrieved %d supported devices in image %s\n", count, image_path);

    fwupd_msg("OPROM Data supported devices:\n");
    for (i = 0; i < count; i++)
    {
         print_device_info(&devices[i]);
    }

out:
    igsc_image_oprom_release(oimg);
    free(img);
    free(devices);

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

    ret = igsc_device_oprom_version(handle, type, &dev_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Cannot initialize device: %s\n", dev_info->name);
        goto exit;
    }
    print_oprom_version(type, &dev_version);

    ret = igsc_image_oprom_match_device(oimg, type, dev_info);
    if (ret == IGSC_SUCCESS)
    {
        update = true;
    }
    else if (ret == IGSC_ERROR_NOT_SUPPORTED)
    {
        update = allow_downgrade;
    }
    else
    {
        fwupd_error("Internal error\n");
        goto exit;
    }

    if (!update)
    {
        fwupd_msg("In order to update run with -a | --allow-downgrade\n");
        ret = EXIT_FAILURE;
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
        fwupd_error("OPROM update failed\n");
    }

    ret = igsc_device_oprom_version(handle, type, &dev_version);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get oprom version after update\n");
        goto exit;
    }
    print_oprom_version(type, &dev_version);

exit:
    igsc_image_oprom_release(oimg);
    free(img);

    return ret;
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
    while((ret = igsc_device_iterator_next(iter, &info)) == IGSC_SUCCESS)
    {
        printf("Device [%d] '%s': %04hx:%04hx %04hx:%04hx %02u:%02u:%02u\n",
               ndevices,
               info.name,
               info.vendor_id, info.device_id,
               info.subsys_vendor_id, info.subsys_device_id,
               info.bus, info.dev, info.func);

        ndevices++;

        ret = igsc_device_init_by_device_info(&handle, &info);
        if (ret != IGSC_SUCCESS)
        {
            /* make sure we have a printable name */
            info.name[0] = '\0';
            continue;
        }

        if (do_info)
        {
            ret = igsc_device_fw_version(&handle, &fw_version);
            if (ret == IGSC_SUCCESS)
            {
                print_fw_version(&fw_version);
            }
            ret = igsc_device_oprom_version(&handle, IGSC_OPROM_CODE, &oprom_version);
            if (ret == IGSC_SUCCESS)
            {
                print_oprom_code_version(&oprom_version);
            }
            ret = igsc_device_oprom_version(&handle, IGSC_OPROM_DATA, &oprom_version);
            if (ret == IGSC_SUCCESS)
            {
                print_oprom_data_version(&oprom_version);
            }
        }
        /* make sure we have a printable name */
        info.name[0] = '\0';
        (void)igsc_device_close(&handle);
    }
    igsc_device_iterator_destroy(iter);
    if (ret == IGSC_ERROR_DEVICE_NOT_FOUND)
    {
        ret = EXIT_SUCCESS;
    }
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
                   NULL},
        .help  = "Update firmware partition or retrieve version from the devices or the supplied image\n"
                 "\nOPTIONS:\n\n"
                 "    -a | --allow-downgrade\n"
                 "            allow downgrade or override the same version\n"
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
                  NULL},
        .help  = "Update oprom code partition or retrieve version from the devices or the supplied image\n"
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
    int ret = EXIT_FAILURE;

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
