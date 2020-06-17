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

#define fwupd_verbose(fmt, ...) do {          \
    if (verbose)                              \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
} while (0)

#define fwupd_error(fmt, ...) do {           \
    fprintf(stderr, fmt, ##__VA_ARGS__);    \
} while (0)


#define MAX_UPDATE_IMAGE_SIZE (8*1024*1024)

struct fw_img {
    uint32_t size;
    uint8_t blob[0];
};

#ifdef __linux__
#define igsc_strdup strdup
static inline int fopen_s(FILE **fp, const char *pathname, const char *mode)
{
    if (!fp)
        return EINVAL;

    errno = 0;
    *fp = fopen(pathname, mode);

    return errno;
}

static void fwupd_strerror(int errnum, char *buf, size_t buflen)
{
    if (strerror_r(errnum, buf, buflen) != 0) {
         strncpy(buf, "Unknown error", buflen);
         buf[buflen - 1] = '\0';
    }
}
#elif defined(WIN32)
#define igsc_strdup _strdup

static void fwupd_strerror(int errnum, char *buf, size_t buflen)
{
    if (strerror_s(buf, buflen, errnum) != 0) {
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

static void print_oprom_version(enum igsc_oprom_type type,
                                const struct igsc_oprom_version *oprom_version)
{
    const char *type_str = type == IGSC_OPROM_DATA ? "DATA" : "CODE";

    printf("OPROM %s Version: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           type_str,
           oprom_version->version[0],
           oprom_version->version[1],
           oprom_version->version[2],
           oprom_version->version[3],
           oprom_version->version[4],
           oprom_version->version[5],
           oprom_version->version[6],
           oprom_version->version[7]);
}

static inline void print_oprom_code_version(const struct igsc_oprom_version *oprom_version)
{
    print_oprom_version(IGSC_OPROM_CODE, oprom_version);
}

static inline void print_oprom_data_version(const struct igsc_oprom_version *oprom_version)
{
    print_oprom_version(IGSC_OPROM_DATA, oprom_version);
}

static struct fw_img *image_read_from_file(const char* p_path)
{
    FILE* fp = NULL;
    struct fw_img *img = NULL;
    long file_size;
    char err_msg[64];

    if (fopen_s(&fp, p_path, "rb") != 0)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to open file %s : %s\n", p_path, err_msg);
        return NULL;
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
        fwupd_verbose("Update Image size (%ld) too large\n", file_size);
        goto exit;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to reset file position %s : %s\n",
                      p_path, err_msg);
        goto exit;
    }

    img = (struct fw_img *)malloc(file_size + sizeof(*img));
    if (img == NULL)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to allocate memory %s\n", err_msg);
        goto exit;
    }

    if (fread(img->blob, 1, file_size, fp) != (size_t)file_size)
    {
        fwupd_strerror(errno, err_msg, sizeof(err_msg));
        fwupd_verbose("Failed to read file %s : %s\n",
                      p_path, err_msg);
        goto exit;
    }

    img->size = file_size;

    fclose(fp);

    return img;

exit:
    free(img);
    fclose(fp);

    return NULL;
}

static int get_first_device(char **device_path)
{
    struct igsc_device_iterator *iter;
    struct igsc_device_info info;
    int ret;

    ret = igsc_device_iterator_create(&iter);
    if (ret != IGSC_SUCCESS) {
        fwupd_error("Cannot create device iterator %d\n", ret);
        return EXIT_FAILURE;
    }
    ret = igsc_device_iterator_next(iter, &info);
    if (ret == IGSC_SUCCESS)
    {
        *device_path = igsc_strdup(info.name);
    }
    igsc_device_iterator_destroy(iter);

    return ret;
}

#define PERCENT_100 100
static void progress_func(uint32_t done, uint32_t total, void *ctx)
{
    char buffer[PERCENT_100 + 1];
    uint32_t percent = (done * PERCENT_100) / total;

    (void)ctx; /* unused */

    memset(buffer, 0, sizeof(buffer));

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

    printf("\b%c[2K\rProgress %d/%d:%2d%%:[%s]\n", 27, done, total, percent, buffer);
    fflush(stdout);
}

static bool arg_is_token(const char *arg, const char *token)
{
    size_t arg_len = strlen(arg);
    size_t token_len = strlen(token);

    return (arg_len == token_len) && !strncmp(arg, token, token_len);
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

static int firmware_update(const char *device_path,
                           const char *image_path,
                           bool allow_downgrade)
{
    struct fw_img *img = NULL;
    struct igsc_device_handle handle;
    struct igsc_fw_version fw_version;
    char *device_path_found = NULL;
    int ret;

    /* FIXME */
    (void)allow_downgrade;

    if (!device_path)
    {
        if (get_first_device(&device_path_found))
        {
            return EXIT_FAILURE;
        }
        device_path = device_path_found;
    }

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        ret = EXIT_FAILURE;
        fwupd_error("Failed to read :%s\n", image_path);
        goto exit;;
    }

    ret = igsc_image_fw_version(img->blob, img->size, &fw_version);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    print_fw_version(&fw_version);

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret)
    {
        fwupd_error("Cannot initialize device %d\n", ret);
        goto exit;
    }

    ret = igsc_device_fw_version(&handle, &fw_version);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }
    print_fw_version(&fw_version);

    ret = igsc_device_fw_update(&handle, img->blob, img->size,
                                 progress_func, NULL);
    if (ret)
    {
        fwupd_error("Cannot update from buffer %d\n", ret);
    }

    ret = igsc_device_fw_version(&handle, &fw_version);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }
    print_fw_version(&fw_version);

    ret = igsc_device_close(&handle);
    if (ret)
    {
        fwupd_error("Cannot close device %d\n", ret);
    }

exit:
    free(img);
    free(device_path_found);
    return ret;
}

static int firmware_version(const char *device_path)
{
    struct igsc_device_handle handle;
    struct igsc_fw_version fw_version;
    int ret;

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    ret = igsc_device_fw_version(&handle, &fw_version);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    print_fw_version(&fw_version);

exit:
    (void)igsc_device_close(&handle);
    return ret;
}

static int image_version(const char *image_path)
{
    struct fw_img *img = NULL;
    struct igsc_fw_version fw_version;
    int ret;

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        return EXIT_FAILURE;
    }

    ret = igsc_image_fw_version(img->blob, img->size, &fw_version);
    if (ret == IGSC_SUCCESS)
    {
        print_fw_version(&fw_version);
    }

    free(img);

    return ret;
}

static int do_firmware_version(int argc, char *argv[])
{
    char *device_path_found = NULL;

    if (argc == 2)
    {
        if (arg_is_token(argv[0], "--device") || arg_is_token(argv[0], "-d"))
        {
            return firmware_version(argv[1]);
        }
        if (arg_is_token(argv[0], "--image") || arg_is_token(argv[0], "-i"))
        {
            return image_version(argv[1]);
        }

        return EXIT_FAILURE;
    }
    else if (argc == 0)
    {
        int ret;

        if (get_first_device(&device_path_found))
        {
            return EXIT_FAILURE;
        }

        ret = firmware_version(device_path_found);
        free(device_path_found);
        return ret;
    }
    return EXIT_FAILURE;
}

static int do_firmware_update(int argc, char *argv[])
{
    bool allow_downgrade = false;
    const char *device_path = NULL;
    const char *image_path = NULL;

    if (argc <= 0)
        return EXIT_FAILURE;

    do
    {
        if (arg_is_token(argv[0], "--allow-downgrade"))
        {
            allow_downgrade = true;
            continue;
        }
        if (arg_is_token(argv[0], "--device") || arg_is_token(argv[0], "-d"))
        {
            if (!arg_next(&argc, &argv))
            {
                return EXIT_FAILURE;
            }
            device_path = argv[0];
        }
        else if (arg_is_token(argv[0], "--image") || arg_is_token(argv[0], "-i"))
        {
            if (!arg_next(&argc, &argv))
            {
                return EXIT_FAILURE;
            }
            image_path = argv[0];
        }
        else
        {
            return EXIT_FAILURE;
        }
    } while(arg_next(&argc, &argv));

    if (image_path)
    {
        return firmware_update(device_path, image_path, allow_downgrade);
    }

    return EXIT_FAILURE;
}

static int do_firmware(int argc, char *argv[])
{
    const char *sub_command = NULL;

    if (argc <= 0)
    {
        return EXIT_FAILURE;
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

    return EXIT_FAILURE;
}


static int do_oprom_code_version(int argc, char *argv[])
{
    struct igsc_device_handle handle;
    struct igsc_oprom_version oprom_version;
    const char *device_path = NULL;
    char *device_path_found = NULL;
    int ret;

    (void)argv;

    if (argc >= 1)
    {
        device_path = argv[0];
    }
    else
    {
        if (get_first_device(&device_path_found))
        {
            return EXIT_FAILURE;
        }
        device_path = device_path_found;
    }

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    ret = igsc_device_oprom_version(&handle, IGSC_OPROM_CODE, &oprom_version);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    print_oprom_code_version(&oprom_version);

exit:
    (void)igsc_device_close(&handle);
    free(device_path_found);
    return ret;
}

static int do_oprom_data_version(int argc, char *argv[])
{
    struct igsc_device_handle handle;
    struct igsc_oprom_version oprom_version;
    const char *device_path = NULL;
    char *device_path_found = NULL;
    int ret;

    (void)argv;

    if (argc >= 1)
    {
        device_path = argv[0];
    }
    else
    {
        if (get_first_device(&device_path_found))
        {
            return EXIT_FAILURE;
        }
        device_path = device_path_found;
    }

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    ret = igsc_device_oprom_version(&handle, IGSC_OPROM_DATA, &oprom_version);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    print_oprom_data_version(&oprom_version);

exit:
    (void)igsc_device_close(&handle);
    free(device_path_found);
    return ret;
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

    if (argc == 1)
    {
        if (arg_is_token(argv[0], "--info") || arg_is_token(argv[0], "-i"))
        {
            do_info = true;
        }
        else
        {
            return EXIT_FAILURE;
        }
    }

    if (arg_next(&argc, &argv))
    {
        return EXIT_FAILURE;
    }

    ret = igsc_device_iterator_create(&iter);
    if (ret != IGSC_SUCCESS) {
        fwupd_error("Cannot create device iterator %d\n", ret);
        return EXIT_FAILURE;
    }

    while((ret = igsc_device_iterator_next(iter, &info)) == IGSC_SUCCESS)
    {
        printf("Device '%s': %04hx:%04hx %04hx:%04hx\n",
               info.name,
               info.vendor_id, info.device_id,
               info.subsys_vendor_id, info.subsys_device_id);

        ret = igsc_device_init_by_device_info(&handle, &info);
        if (ret != IGSC_SUCCESS)
        {
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

        (void)igsc_device_close(&handle);
    }
    igsc_device_iterator_destroy(iter);
    if (ret == IGSC_ERROR_DEVICE_NOT_FOUND)
    {
        ret = EXIT_SUCCESS;
    }

    return ret;
}

static int do_oprom_image_info(int argc, char *argv[])
{
    struct fw_img *img = NULL;
    struct igsc_oprom_version oprom_version;
    const char *image_path = NULL;
    struct igsc_oprom_image *oimg = NULL;
    enum igsc_oprom_type type;
    struct igsc_oprom_device_info one_dev;
    int ret;

    if (argc <= 0)
    {
        return EXIT_FAILURE;
    }

    image_path = argv[0];

    img = image_read_from_file(image_path);
    if (img == NULL)
    {
        fwupd_error("Failed to read :%s\n", image_path);
        return EXIT_FAILURE;
    }

    ret = igsc_image_oprom_init(&oimg, img->blob, img->size);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to init :%s\n", image_path);
        goto out;
    }
    ret = igsc_image_oprom_type(oimg, &type);
    if (ret != IGSC_SUCCESS)
    {
        fwupd_error("Failed to get oprom image type\n");
        goto release;
    }
    printf("OPROM Type: %d\n", type);
    ret = igsc_image_oprom_version(oimg, &oprom_version);
    if (ret != IGSC_SUCCESS)
    {
        goto release;
    }
    print_oprom_version(type, &oprom_version);
    while ((ret = igsc_image_oprom_iterator_next(oimg, &one_dev)) == IGSC_SUCCESS)
    {
        printf("OPROM supported device: %04X:%04X\n",
               one_dev.subsys_vendor_id, one_dev.subsys_device_id);
    }
    if (ret == IGSC_ERROR_DEVICE_NOT_FOUND)
    {
        ret = IGSC_SUCCESS;
    }

release:
    igsc_image_oprom_release(oimg);
out:
    free(img);

    return ret;
}

static int do_oprom_update(int argc, char *argv[])
{
    struct fw_img *img = NULL;
    struct igsc_oprom_image *oimg = NULL;
    struct igsc_device_handle handle;
    struct igsc_oprom_version oprom_version;
    const char *image_path = NULL;
    const char *device_path = NULL;
    char *device_path_found = NULL;
    enum igsc_oprom_type type;
    enum igsc_oprom_type type_img;
    int ret;

    if (argc <= 0)
        return EXIT_FAILURE;

    type = atoi(argv[0]);
    if (!arg_next(&argc, &argv))
    {
        return EXIT_FAILURE;
    }

    image_path = argv[0];
    if (!arg_next(&argc, &argv))
    {
        return EXIT_FAILURE;
    }

    if (argc >= 1)
    {
        device_path = argv[0];
    }
    else
    {
        if (get_first_device(&device_path_found))
        {
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

    ret = igsc_image_oprom_init(&oimg, img->blob, img->size);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }
    ret = igsc_image_oprom_type(oimg, &type_img);
    if (ret != IGSC_SUCCESS)
    {
        goto release;
    }
    printf("OPROM Type: %d\n", type_img);
    if (type != type_img)
    {
        ret = EXIT_FAILURE;
        fwupd_error("Image type is different: %d?=%d\n", type, type_img);
        goto release;
    }
    ret = igsc_image_oprom_version(oimg, &oprom_version);
    if (ret != IGSC_SUCCESS)
    {
        goto release;
    }
    print_oprom_version(type, &oprom_version);

release:
    igsc_image_oprom_release(oimg);

    ret = igsc_device_init_by_device(&handle, device_path);
    if (ret)
    {
        fwupd_error("Cannot initialize device %d\n", ret);
        goto exit;
    }

    ret = igsc_device_oprom_version(&handle, type, &oprom_version);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }
    print_oprom_version(type, &oprom_version);

    ret = igsc_device_oprom_update(&handle, type, img->blob, img->size,
                                   progress_func, NULL);
    if (ret)
    {
        fwupd_error("Cannot update from buffer %d\n", ret);
    }

    ret = igsc_device_oprom_version(&handle, type, &oprom_version);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }
    print_oprom_version(type, &oprom_version);

    ret = igsc_device_close(&handle);
    if (ret)
    {
        fwupd_error("Cannot close device %d\n", ret);
    }

exit:
    free(img);
    free(device_path_found);
    return ret;
}

typedef int (*fwupd_op)(int argc, char *argv[]);

struct fwupd_op {
    const char *name;
    fwupd_op    op;
    const char  *usage; /* usage title */
    const char  *help;  /* help */
};

static const struct fwupd_op ops[] = {
    {
        .name  = "fw",
        .op    = do_firmware,
        .usage = "update <image> [<dev>]\nversion [--device <dev>] | [--image <file>] ",
        .help  = "    update device image\n",
    },
    {
        .name  = "oprom-code-version",
        .op    = do_oprom_code_version,
        .usage = "[<dev>]",
        .help  = "    version of the installed oprom code\n",
    },
    {
        .name  = "oprom-data-version",
        .op    = do_oprom_data_version,
        .usage = "[<dev>]",
        .help  = "    version of the installed oprom data\n",
    },
    {
        .name  = "list-devices",
        .op    = do_list_devices,
        .usage = "[--info]",
        .help  = "    list devices supporting fw update\n",
    },
    {
        .name  = "oprom-image-info",
        .op    = do_oprom_image_info,
        .usage = "<image>",
        .help  = "    print oprom image info\n",
    },
    {
        .name  = "oprom-update",
        .op    = do_oprom_update,
        .usage = "<type> <image> [<dev>]",
        .help  = "    update OPROM image\n",
    },
    {
        .name  = NULL,
    }
};

static void help(const char *exec_name, const struct fwupd_op *op)
{
    printf("%s %s %s\n", exec_name, op->name, op->usage);
    printf("%s\n", op->help);
}

static void usage(const char *exe_name)
{
    unsigned int i;

    printf("\n");
    printf("Usage: %s [-v] <command> <args>\n\n", exe_name);
    for (i = 0; ops[i].name; i++)
        printf("    %s %s %s\n",
               exe_name, ops[i].name, ops[i].usage);

    printf("\n");
    printf("    %s -v/--verbose: runs in verbose mode\n", exe_name);
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

static const
struct fwupd_op *args_parse(const char *exe_name, int *argc, char **argv[])
{
    unsigned int i;
    const struct fwupd_op *op = NULL;
    bool display_help = false;

    if (!arg_next(argc, argv))
    {
        goto out;
    }

    if (arg_is_help(*argv[0]))
    {
        if (!arg_next(argc, argv))
        {
            goto out;
        }
        display_help = true;
    }

    if (arg_is_verbose(*argv[0]))
    {
        if (!arg_next(argc, argv))
        {
            goto out;
        }
        verbose = true;
    }

    for (i = 0; ops[i].name; i++)
    {
        if (!strncmp(*argv[0], ops[i].name, strlen(ops[i].name)))
        {
            op = &ops[i];
            arg_next(argc, argv);
            break;
        }
    }

    if (op == NULL)
    {
        usage(exe_name);
        return NULL;
    }

    if (display_help || (*argc > 0 && arg_is_help(*argv[0])))
    {
        help(exe_name, op);
        arg_next(argc, argv);
        op = NULL;
    }

    return op;

out:
    usage(exe_name);
    return NULL;
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

    return strdup(p);
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
   strcat_s(str, str_len, fname);
   strcat_s(str, str_len, ext);

   return str;
}
#endif

int main(int argc, char* argv[])
{
    char *exec_name = prog_name(argv[0]);
    const struct fwupd_op *op = NULL;
    int ret;

    op = args_parse(exec_name, &argc, &argv);
    if (!op)
    {
        return EXIT_SUCCESS;
    }

    ret = op->op(argc, argv);
    if (ret)
    {
        help(exec_name, op);
    }

    free(exec_name);

    return (ret) ? EXIT_FAILURE : EXIT_SUCCESS;
}
