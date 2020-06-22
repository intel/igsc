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

#include "msvc/config.h"

#include "igsc_system.h"
#include "igsc_heci.h"

#include <metee.h>

#ifdef UNIT_TESTING
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#define  mockable_static __attribute__((weak))
#else
#define  mockable_static static
#endif

#include "igsc_lib.h"
#include "igsc_perf.h"
#include "igsc_log.h"

#include "utils.h"

/*
 * FIXME: cmocka cannot track strudp allocation need to craft our own
 */
char *gsc_strdup(const char *s)
{
    size_t len = strlen(s);
    char *d = calloc(1, len + 1);
    if (d == NULL)
    {
        return NULL;
    }
    gsc_memcpy_s(d, len + 1, s, len + 1);
    return d;
}

DEFINE_GUID(GUID_METEE_FWU, 0x87d90ca5, 0x3495, 0x4559,
            0x81, 0x05, 0x3f, 0xbf, 0xa3, 0x7b, 0x8b, 0x79);

#define INFO_HEADER_MARKER (0x4f464e49)
#define FWIM_HEADER_MARKER (0x4d495746)

enum FWU_FPT_ENTRY {
    FWU_FPT_ENTRY_IMAGE_INFO,
    FWU_FPT_ENTRY_FW_IMAGE,
    FWU_FPT_ENTRY_NUM
};

struct gsc_fwu_img_entry {
    const uint8_t *content;
    uint32_t size;
};

struct gsc_fwu_img_layout {
    struct gsc_fwu_img_entry table[FWU_FPT_ENTRY_NUM];
};

#define ENTRY_ID_TO_BITMASK(entry_id) (1 << (entry_id))

#define MANDATORY_ENTRY_BITMASK \
       (ENTRY_ID_TO_BITMASK(FWU_FPT_ENTRY_IMAGE_INFO) | \
        ENTRY_ID_TO_BITMASK(FWU_FPT_ENTRY_FW_IMAGE))

struct igsc_lib_ctx {
    char *device_path;                /**< GSC device path */
    igsc_handle_t dev_handle;         /**< GSC device handle */
    TEEHANDLE driver_handle;          /**< Context for the driver */
    uint8_t *working_buffer;          /**< Buffer for tee calls */
    size_t working_buffer_length;     /**< Tee buffer length */
    bool driver_init_called;          /**< Driver was initialized */
    struct gsc_fwu_img_layout layout; /**< Context for the image layout */
};

#define FWSTS(n) ((n) - 1)

static int status_tee2fu(TEESTATUS status)
{
    switch (status) {
    case TEE_SUCCESS:
        return IGSC_SUCCESS;
    case TEE_INTERNAL_ERROR:
        return IGSC_ERROR_INTERNAL;
    case TEE_DEVICE_NOT_FOUND:
        return IGSC_ERROR_DEVICE_NOT_FOUND;
    default:
        return IGSC_ERROR_INTERNAL;
    }
}

mockable_static
void driver_working_buffer_free(struct igsc_lib_ctx *lib_ctx)
{
    free(lib_ctx->working_buffer);
    lib_ctx->working_buffer = NULL;
    lib_ctx->working_buffer_length = 0;
}

mockable_static
int driver_working_buffer_alloc(struct igsc_lib_ctx *lib_ctx)
{
    size_t buf_len;

    if (lib_ctx->working_buffer_length == lib_ctx->driver_handle.maxMsgLen)
    {
        return IGSC_SUCCESS;
    }

    driver_working_buffer_free(lib_ctx);

    buf_len = lib_ctx->driver_handle.maxMsgLen;
    lib_ctx->working_buffer = (uint8_t *)malloc(buf_len);
    if (lib_ctx->working_buffer == NULL)
    {
        gsc_error("Cannot allocate working buffer\n");
        return IGSC_ERROR_NOMEM;
    }

    lib_ctx->working_buffer_length = buf_len;

    return IGSC_SUCCESS;
}


mockable_static
void driver_deinit(struct igsc_lib_ctx *lib_ctx)
{
    if (!lib_ctx->driver_init_called)
    {
        return;
    }

    driver_working_buffer_free(lib_ctx);

    TeeDisconnect(&lib_ctx->driver_handle);

    lib_ctx->driver_init_called = false;
}

mockable_static
int driver_init(struct igsc_lib_ctx *lib_ctx)
{
    TEESTATUS tee_status;
    int status;

    tee_status = TeeInit(&lib_ctx->driver_handle, &GUID_METEE_FWU, lib_ctx->device_path);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        gsc_error("Error in HECI init (%d)\n", tee_status);
        status = status_tee2fu(tee_status);
        goto exit;
    }

    tee_status = TeeConnect(&lib_ctx->driver_handle);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        gsc_error("Error in HECI connect (%d)\n", tee_status);
        status = status_tee2fu(tee_status);
        goto exit;
    }

    status = driver_working_buffer_alloc(lib_ctx);
    if (status != IGSC_SUCCESS)
    {
        TeeDisconnect(&lib_ctx->driver_handle);
        goto exit;
    }

    lib_ctx->driver_init_called = true;

    status = IGSC_SUCCESS;

exit:
    return status;
}

static int driver_reconnect(struct igsc_lib_ctx *lib_ctx)
{
    TEESTATUS tee_status;
    int status;

    tee_status = TeeConnect(&lib_ctx->driver_handle);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        gsc_error("Error in HECI connect (%d)\n", tee_status);
        status = status_tee2fu(tee_status);
        goto exit;
    }

    status = driver_working_buffer_alloc(lib_ctx);
    if (status != IGSC_SUCCESS)
    {
        TeeDisconnect(&lib_ctx->driver_handle);
        goto exit;
    }

    lib_ctx->driver_init_called = true;

    status = IGSC_SUCCESS;

exit:
    return status;
}

static void gsc_fwu_img_layout_reset(struct gsc_fwu_img_layout *layout)
{
    memset(layout, 0, sizeof(*layout));
}

static bool is_empty(const uint8_t *buf, size_t size)
{
    size_t i;

    for (i = 0; i < size; i++)
    {
        if (buf[i] != 0)
        {
            return false;
        }
    }
    return true;
}

static int gsc_fwu_img_layout_parse(struct gsc_fwu_img_layout *layout,
                                    const uint8_t *buffer, uint32_t buffer_len)
{
    int status;
    uint32_t i;
    uint32_t entries_found_bitmask = 0;
    size_t total_size;
    const struct gsc_fwu_fpt_img *fpt;

    if (buffer_len < sizeof(fpt->header))
    {
        gsc_error("Image size (%d) too small to contain FPT Header\n",
                buffer_len);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    if (buffer_len > IGSC_MAX_IMAGE_SIZE)
    {
        gsc_error("Image size (%d) too big\n", buffer_len);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    fpt = (const struct gsc_fwu_fpt_img *)buffer;
    if (fpt->header.header_marker != FPT_HEADER_MARKER)
    {
        gsc_error("Invalid FPT header marker (0x%x)\n",
                fpt->header.header_marker);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    if (fpt->header.num_of_entries < FWU_FPT_ENTRY_NUM ||
        fpt->header.num_of_entries > FPT_MAX_ENTERIES)
    {
        gsc_error("Invalid FPT number of entries (%d)\n",
                fpt->header.num_of_entries);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    total_size = sizeof(fpt->header) +
                 fpt->header.num_of_entries * sizeof(struct gsc_fwu_fpt_entry);

    if (buffer_len < total_size)
    {
        gsc_error("Image size (%d) can't hold %d entries\n",
                buffer_len, fpt->header.num_of_entries);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    if (fpt->header.header_version != FPT_HEADER_VERSION)
    {
        gsc_error("Invalid FPT header version (0x%x)\n",
                fpt->header.header_version);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    if (fpt->header.entry_version != FPT_ENTRY_VERSION)
    {
        gsc_error("Invalid FPT entry version (0x%x)\n",
                fpt->header.entry_version);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    if (fpt->header.header_length != FPT_HEADER_LENGTH)
    {
        gsc_error("Invalid FPT header length (0x%x)\n",
                fpt->header.header_length);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    for (i = 0; i < fpt->header.num_of_entries; i++)
    {
        const struct gsc_fwu_fpt_entry *entry = &fpt->entry[i];
        uint32_t entry_id;

        if (!is_empty(entry->reserved1, sizeof(entry->reserved1)))
        {
            gsc_error("Invalid value for reserved1 in FPT entry 0x%x\n",
                    entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        if (entry->offset < total_size)
        {
            gsc_error("Invalid value for offset in FPT entry 0x%x\n",
                    entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        if (entry->offset > buffer_len)
        {
            gsc_error("Invalid value for offset in FPT entry 0x%x\n",
                    entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        if (entry->length > buffer_len)
        {
            gsc_error("Invalid length for offset in FPT entry 0x%x\n",
                    entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        if (entry->offset + entry->length > buffer_len)
        {
            gsc_error("Invalid value for offset in FPT entry 0x%x\n",
                    entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        if (!is_empty(entry->reserved2, sizeof(entry->reserved2)))
        {
            gsc_error("Invalid value for reserved2 in FPT entry 0x%x\n",
                    entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        if (entry->partition_flags.entry_valid == 0xFF)
        {
            gsc_error("FPT entry 0x%x marked as invalid\n",
                    entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        switch (entry->partition_name)
        {
            case INFO_HEADER_MARKER:
                entry_id = FWU_FPT_ENTRY_IMAGE_INFO;
                break;
            case FWIM_HEADER_MARKER:
                entry_id = FWU_FPT_ENTRY_FW_IMAGE;
                break;
            default:
                entry_id = FWU_FPT_ENTRY_NUM;
                break;
        }

        if (entry_id == FWU_FPT_ENTRY_NUM)
        {
            continue;
        }

        if (entries_found_bitmask & ENTRY_ID_TO_BITMASK(entry_id))
        {
            gsc_error("FPT entry 0x%x already encountered\n",
                    entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        entries_found_bitmask |= ENTRY_ID_TO_BITMASK(entry_id);

        if (entry_id >= _countof(layout->table))
        {
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        layout->table[entry_id].content = buffer + entry->offset;
        layout->table[entry_id].size = entry->length;
        gsc_debug("FPT entries %d len %d\n", entry_id, entry->length);
    }

    if ((entries_found_bitmask & MANDATORY_ENTRY_BITMASK) != MANDATORY_ENTRY_BITMASK)
    {
        gsc_debug("Mandatory FPT entries missing from update image\n");
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    status = IGSC_SUCCESS;
exit:
    return status;
}

static int gsc_fwu_buffer_validate(struct igsc_lib_ctx *lib_ctx,
                              size_t req_sz, size_t resp_sz)
{
    if (lib_ctx->working_buffer == NULL)
    {
        return IGSC_ERROR_INTERNAL;
    }

    if (lib_ctx->working_buffer_length < req_sz)
    {
        return IGSC_ERROR_INTERNAL;
    }

    if (lib_ctx->working_buffer_length < resp_sz)
    {
        return IGSC_ERROR_INTERNAL;
    }

    return IGSC_SUCCESS;
}

static int gsc_fwu_heci_validate_response_header(struct gsc_fwu_heci_response *resp_header,
                                                 enum gsc_fwu_heci_command_id command_id)
{
    int status;

    if (resp_header == NULL)
    {
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    if (resp_header->header.command_id != command_id)
    {
        gsc_debug("Invalid command ID (%d)\n",
                resp_header->header.command_id);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->header.is_response != true)
    {
        gsc_debug("HECI Response not marked as response\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->status != GSC_FWU_STATUS_SUCCESS)
    {
        const char *msg;
        switch(resp_header->status) {
        case GSC_FWU_STATUS_SIZE_ERROR:
            msg = "Num of bytes to read/write/erase is bigger than partition size";
            break;
        case GSC_FWU_STATUS_UPDATE_OPROM_INVALID_STRUCTURE:
            msg = "Wrong oprom signature";
            break;
        case GSC_FWU_STATUS_UPDATE_OPROM_SECTION_NOT_EXIST:
            msg = "Update oprom section does not exists on flash";
            break;
        case GSC_FWU_STATUS_INVALID_COMMAND:
            msg = "Invalid HECI message sent";
            break;
        case GSC_FWU_STATUS_INVALID_PARAMS:
            msg = "Invalid command parameters";
            break;
        case GSC_FWU_STATUS_FAILURE:
        /* fall through */
        default:
            msg = "General firmware error";
            break;
        }
        gsc_error("HECI message failed with status %s 0x%x\n",
                msg, resp_header->status);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->reserved != 0)
    {
        gsc_error("HECI message response is leaking data\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}

mockable_static
int gsc_tee_command(struct igsc_lib_ctx *lib_ctx,
                    void *req_buf, size_t request_len,
                    void *resp_buf, size_t buf_size,
                    size_t *response_len)
{
    size_t num_bytes;
    int status;
    TEESTATUS tee_status;

    num_bytes = 0;
    tee_status = TeeWrite(&lib_ctx->driver_handle, req_buf, request_len, &num_bytes, 0);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        gsc_error("Error in HECI write (%d)\n", tee_status);
        status = status_tee2fu(tee_status);
        goto exit;
    }
    if (num_bytes != request_len)
    {
        gsc_error("Error in HECI write - bad size (%zu)\n", num_bytes);
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    tee_status = TeeRead(&lib_ctx->driver_handle, resp_buf, buf_size, response_len, 0);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        gsc_error("Error in HECI read %d\n", tee_status);
        status = status_tee2fu(tee_status);
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}


static int gsc_fwu_get_version(struct igsc_lib_ctx *lib_ctx,
                               uint32_t partition,
                               uint32_t version_length, void **version)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len;

    struct gsc_fwu_heci_version_resp *resp;
    struct gsc_fwu_heci_version_req *req;
    enum gsc_fwu_heci_command_id command_id = GSC_FWU_HECI_COMMAND_ID_GET_IP_VERSION;

    if (version == NULL)
    {
        return IGSC_ERROR_INTERNAL;
    }

    req = (struct gsc_fwu_heci_version_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gsc_fwu_heci_version_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp) + version_length;
    buf_len = lib_ctx->working_buffer_length;

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        return status;
    }

    memset(req, 0, request_len);
    req->header.command_id = command_id;
    req->partition = partition;
    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->response))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = gsc_fwu_heci_validate_response_header(&resp->response, command_id);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len != response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->partition != partition)
    {
        gsc_error("Invalid HECI message response payload (%u)\n", resp->partition);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->version_length != version_length)
    {
        gsc_error("Invalid HECI message response version_length (%u)\n", resp->version_length);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    *version = &resp->version;
    status = IGSC_SUCCESS;

exit:
    return status;
}

static void gsc_fw_copy_version(struct igsc_fw_version* version,
                                struct gsc_fwu_external_version *overall_version)
{
    version->project[0] = overall_version->project[0];
    version->project[1] = overall_version->project[1];
    version->project[2] = overall_version->project[2];
    version->project[3] = overall_version->project[3];
    version->hotfix = overall_version->hotfix;
    version->build = overall_version->build;
}

static int gsc_get_fw_version(struct igsc_lib_ctx *lib_ctx,
                              struct igsc_fw_version *version)
{
    int status;
    void *pnt = NULL;

    status = gsc_fwu_get_version(lib_ctx, GSC_FWU_HECI_PART_VERSION_GFX_FW,
                                 sizeof(*version), &pnt);
    if (!status)
    {
        gsc_fw_copy_version(version, pnt);
    }
    return status;
}

static int gsc_fwu_get_oprom_version(struct igsc_lib_ctx *lib_ctx,
                                     uint32_t partition,
                                     struct igsc_oprom_version *version)
{
    int  status;
    void *pnt = NULL;

    status = gsc_fwu_get_version(lib_ctx, partition,
                                 sizeof(*version), &pnt);
    if (!status)
    {
        if (gsc_memcpy_s(version->version, IGSC_OPROM_VER_SIZE,
                         pnt, IGSC_OPROM_VER_SIZE))
        {
            gsc_error("Copy of version data failed\n");
            status = IGSC_ERROR_INTERNAL;
        }
    }
    return status;
}

static int gsc_fwu_start(struct igsc_lib_ctx *lib_ctx, uint32_t payload_type)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len;
    const uint8_t *fpt_info;
    uint32_t fpt_info_len;

    struct gsc_fwu_heci_start_req  *req;
    struct gsc_fwu_heci_start_resp *resp;
    enum gsc_fwu_heci_command_id command_id = GSC_FWU_HECI_COMMAND_ID_START;

    req = (struct gsc_fwu_heci_start_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gsc_fwu_heci_start_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    fpt_info_len = lib_ctx->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].size;
    fpt_info = lib_ctx->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].content;

    request_len += fpt_info_len;
    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        return status;
    }

    memset(req, 0, request_len);
    req->header.command_id = command_id;

    req->update_img_length = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size;
    req->payload_type = payload_type;
    req->flags = 0;
    memset(req->reserved, 0, sizeof(req->reserved));
    if (gsc_memcpy_s(&req->data, buf_len - sizeof(*req), fpt_info, fpt_info_len))
    {
        gsc_error("Copy of meta data failed\n");
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->response))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = gsc_fwu_heci_validate_response_header(&resp->response, command_id);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
    }

    if (received_len != response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

exit:
    return status;
}

static uint32_t gsc_fwu_chunk_size(struct igsc_lib_ctx *lib_ctx, uint32_t req_size)
{
    return min(req_size,
               (uint32_t)(lib_ctx->driver_handle.maxMsgLen -
                          sizeof(struct gsc_fwu_heci_data_req)));
}

static int gsc_fwu_data(struct igsc_lib_ctx *lib_ctx,
                        const uint8_t *data, uint32_t length)
{
    int    status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len = lib_ctx->working_buffer_length;

    struct gsc_fwu_heci_data_req  *req;
    struct gsc_fwu_heci_data_resp *resp;
    enum gsc_fwu_heci_command_id command_id = GSC_FWU_HECI_COMMAND_ID_DATA;

    req = (struct gsc_fwu_heci_data_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req) + length;

    resp = (struct gsc_fwu_heci_data_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status)
    {
        return status;
    }

    memset(req, 0, sizeof(req->header));
    req->header.command_id = command_id;
    req->data_length = length;
    if (gsc_memcpy_s(req->data, buf_len - sizeof(*req), data, length))
    {
        gsc_error("Copy of request has failed\n");
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->response))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = gsc_fwu_heci_validate_response_header(&resp->response, command_id);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response (%d)\n", status);
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    if (received_len != response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}

static int gsc_fwu_end(struct igsc_lib_ctx *lib_ctx)
{
    TEESTATUS tee_status;
    int       status;
    size_t    request_len;

    struct gsc_fwu_heci_end_req *req;
    enum   gsc_fwu_heci_command_id command_id = GSC_FWU_HECI_COMMAND_ID_END;

    req = (struct gsc_fwu_heci_end_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    status = gsc_fwu_buffer_validate(lib_ctx, sizeof(*req), 0);
    if (status)
    {
        return status;
    }

    memset(req, 0, sizeof(req->header));
    req->header.command_id = command_id;
    req->reserved = 0;

    tee_status = TeeWrite(&lib_ctx->driver_handle, req, request_len, NULL, 0);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        gsc_error("Error in HECI write (%d)\n", tee_status);
        status = status_tee2fu(tee_status);
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}

static int get_fwsts(struct igsc_lib_ctx *lib_ctx,
                     uint32_t fwsts_index, uint32_t *value)
{
    TEESTATUS tee_status;

    if (value == NULL)
    {
        return IGSC_ERROR_INTERNAL;
    }

    tee_status = TeeFWStatus(&lib_ctx->driver_handle, fwsts_index, value);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        return status_tee2fu(tee_status);
    }

    return IGSC_SUCCESS;
}

static bool gsc_fwu_is_in_progress(struct igsc_lib_ctx *lib_ctx)
{
    int status;
    bool is_in_progress = false;
    bool init_completed;
    bool fu_idle;

    uint32_t value;

    status = get_fwsts(lib_ctx, FWSTS(1), &value);
    if (status != IGSC_SUCCESS)
    {
        is_in_progress = true;
        goto exit;
    }

    init_completed = ( ((value >> 9) & 0x1) == HECI1_CSE_FS_INITSTATE_COMPLETED);
    fu_idle = ( ((value >> 11) & 0x1) == HECI1_CSE_FS_FWUPDATE_STATE_IDLE);

    if (init_completed && fu_idle)
    {
        is_in_progress = false;
    }
    else
    {
        is_in_progress = true;
    }

    status = IGSC_SUCCESS;

exit:
    return is_in_progress;
}


static int get_percentage(struct igsc_lib_ctx *lib_ctx, uint32_t *percentage)
{
    int status;

    uint32_t value;
    uint32_t fwsts_phase;
    uint32_t fwsts_value;

    if (percentage == NULL)
    {
        return IGSC_ERROR_INTERNAL;
    }

    status = get_fwsts(lib_ctx, FWSTS(2), &value);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Error in get FW status (%d)\n", status);
        goto exit;
    }

    fwsts_phase = (value >> 28) & 0xF;
    fwsts_value = (value >> 16) & 0xFF;

    if (fwsts_phase != HECI1_CSE_GS1_PHASE_FWUPDATE)
    {
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    *percentage = fwsts_value;

    status = IGSC_SUCCESS;

exit:
    return status;
}

/* OPROM helpers */
static enum gsc_fwu_heci_partition_version
oprom_type_to_partition(uint32_t oprom_type)
{
    if (oprom_type == IGSC_OPROM_DATA)
    {
        return GSC_FWU_HECI_PART_VERSION_OPROM_DATA;
    }
    if (oprom_type == IGSC_OPROM_CODE)
    {
        return GSC_FWU_HECI_PART_VERSION_OPROM_CODE;
    }

    return GSC_FWU_HECI_PART_VERSION_INVALID;
}

/* FW Update API */

int igsc_device_init_by_device(IN OUT struct igsc_device_handle *handle,
                               IN const char *device_path)
{
    if (handle == NULL || device_path == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    handle->ctx = calloc(1, sizeof(*handle->ctx));
    if (handle->ctx == NULL)
    {
        gsc_error("Context Allocation failed\n");
        return IGSC_ERROR_NOMEM;
    }

    handle->ctx->device_path = gsc_strdup(device_path);
    if (handle->ctx->device_path == NULL)
    {
        gsc_error("Path Allocation failed\n");
        free(handle->ctx);
        handle->ctx = NULL;
        return IGSC_ERROR_NOMEM;
    }

    return IGSC_SUCCESS;
}

int igsc_device_init_by_handle(IN OUT struct igsc_device_handle *handle,
                               IN igsc_handle_t dev_handle)
{
    if (handle == NULL || dev_handle == 0)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

#if 0
    handle->ctx = calloc(1, sizeof(*handle->ctx));
    if (handle->ctx == NULL)
    {
        gsc_error("Context Allocation failed\n");
        return IGSC_ERROR_NOMEM;
    }
    handle->ctx->dev_handle = dev_handle;

    return IGSC_SUCCESS;
#else
    /* TODO not supported by MeTee */
    return IGSC_ERROR_NOT_SUPPORTED;

#endif /* 0 */
}

int igsc_device_init_by_device_info(IN OUT struct igsc_device_handle *handle,
                                    IN const struct igsc_device_info *dev_info)
{
    if (handle == NULL || dev_info == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return igsc_device_init_by_device(handle, dev_info->name);
}

int igsc_device_close(IN OUT struct igsc_device_handle *handle)
{

    if (handle == NULL)
    {
        gsc_error("Bad parameter\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (handle->ctx)
    {
        if (handle->ctx->device_path)
            free(handle->ctx->device_path);
        free(handle->ctx);
        handle->ctx = NULL;
    }

    return IGSC_SUCCESS;
}

int igsc_device_fw_version(IN struct igsc_device_handle *handle,
                           OUT struct igsc_fw_version *version)
{
    struct igsc_lib_ctx *lib_ctx;
    int ret;

    if (handle == NULL || handle->ctx == NULL || version == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;
    ret = driver_init(lib_ctx);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to init HECI driver\n");
        return ret;
    }

    ret = gsc_get_fw_version(lib_ctx, version);

    driver_deinit(lib_ctx);

    return ret;
}

int igsc_image_fw_version(IN  const uint8_t *buffer,
                          IN  uint32_t buffer_len,
                          OUT struct igsc_fw_version *version)
{
    int    ret;
    struct gsc_fwu_img_layout layout;

    struct gsc_fwu_heci_image_metadata *meta;
    struct gsc_fwu_image_metadata_v1 *meta_v1;
    uint32_t meta_len;

    if (buffer == NULL || buffer_len == 0 || version == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    gsc_fwu_img_layout_reset(&layout);

    /*
     * Parse the image, check that the image layout is correct and store it in
     * the library context
     */
    ret = gsc_fwu_img_layout_parse(&layout, buffer, buffer_len);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    gsc_debug("Update Image Payload size: %d bytes\n",
             layout.table[FWU_FPT_ENTRY_FW_IMAGE].size);

    meta = (struct gsc_fwu_heci_image_metadata *)layout.table[FWU_FPT_ENTRY_IMAGE_INFO].content;
    meta_len = layout.table[FWU_FPT_ENTRY_IMAGE_INFO].size;

    if (meta->metadata_format_version != GSC_FWU_HECI_METADATA_VERSION_1)
    {
        /* Note that it's still ok to use the V1 metadata struct to get the
         * FW version because the FW version position and structure stays
         * the same in all versions of the struct
         */
        gsc_error("Metadata format version is %d, instead of expected V1 (%d)\n",
                  meta->metadata_format_version,
                  GSC_FWU_HECI_METADATA_VERSION_1);
    }

    if (meta_len < sizeof(*meta) + sizeof(*meta_v1))
    {
        gsc_error("Firmware is corrupted\n");
        return IGSC_ERROR_BAD_IMAGE;
    }

    meta_v1 = (struct gsc_fwu_image_metadata_v1 *)meta->metadata;

    gsc_fw_copy_version(version, &meta_v1->overall_version);

    return IGSC_SUCCESS;
}

int igsc_device_fw_update(IN struct igsc_device_handle *handle,
                          IN const uint8_t *buffer,
                          IN const uint32_t buffer_len,
                          IN igsc_progress_func_t progress_f,
                          IN void *ctx)
{
    struct igsc_lib_ctx *lib_ctx;
    int      ret;
    uint32_t bytes_sent = 0;
    uint32_t chunk_size = 0;
    uint32_t data_counter = 0;
    uint32_t percentage;
    uint32_t fpt_size = 0;
    const uint8_t *fpt_data = NULL;

    struct gsc_perf_cnt _perf_ctx;
    struct gsc_perf_cnt *perf_ctx = &_perf_ctx;

    if (handle == NULL || handle->ctx == NULL ||
        buffer == NULL || buffer_len == 0)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_pref_cnt_init(perf_ctx);
    gsc_pref_cnt_checkpoint(perf_ctx, "Program start");

    ret = gsc_fwu_img_layout_parse(&lib_ctx->layout, buffer, buffer_len);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    fpt_size = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size;
    fpt_data = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].content;

    gsc_debug("Update Image Payload size: %d bytes\n", fpt_size);

    gsc_pref_cnt_checkpoint(perf_ctx, "After reading and parsing image");

    ret = driver_init(lib_ctx);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "Before FWU_START");

    ret = gsc_fwu_start(lib_ctx, GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After FWU_START");

    while (bytes_sent < fpt_size)
    {
        if (get_percentage(lib_ctx, &percentage) == IGSC_SUCCESS)
        {
            if (progress_f)
            {
                progress_f(percentage, 100, ctx);
            }
        }

        chunk_size = gsc_fwu_chunk_size(lib_ctx, fpt_size - bytes_sent);
        ret = gsc_fwu_data(lib_ctx, fpt_data + bytes_sent, chunk_size);
        if (ret != IGSC_SUCCESS)
        {
            goto exit;
        }
        bytes_sent += chunk_size;
        data_counter++;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After FWU_DATA");

    gsc_debug("Update Image sent to FW via %d FWU_DATA messages\n",
              data_counter);

    ret = gsc_fwu_end(lib_ctx);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After FWU_END");

    while (gsc_fwu_is_in_progress(lib_ctx))
    {
        if (get_percentage(lib_ctx, &percentage) == IGSC_SUCCESS)
        {
            if (progress_f)
            {
                progress_f(percentage, 100, ctx);
            }
        }
        else
        {
            gsc_msleep(100);
        }
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After PLRs");

    driver_reconnect(lib_ctx);

exit:
    gsc_fwu_img_layout_reset(&lib_ctx->layout);

    driver_deinit(lib_ctx);

    return ret;
}

/* OPROM API */
int igsc_device_oprom_version(IN struct igsc_device_handle *handle,
                              IN uint32_t oprom_type,
                              OUT struct igsc_oprom_version *version)
{
    struct igsc_lib_ctx *lib_ctx;
    uint32_t partition;
    int ret;

    if (handle == NULL || handle->ctx == NULL || version == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    partition = oprom_type_to_partition(oprom_type);
    if (partition == GSC_FWU_HECI_PART_VERSION_INVALID)
    {
        gsc_error("Bad oprom type %d\n", oprom_type);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;
    ret = driver_init(lib_ctx);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to init HECI driver\n");
        return ret;
    }

    ret = gsc_fwu_get_oprom_version(lib_ctx, partition, version);

    driver_deinit(lib_ctx);

    return ret;
}

int igsc_device_oprom_update(IN  struct igsc_device_handle *handle,
                             IN  uint32_t oprom_type,
                             IN  const uint8_t *buffer,
                             IN  const uint32_t buffer_len,
                             IN  igsc_progress_func_t progress_f,
                             IN  void *ctx)
{
    struct igsc_lib_ctx *lib_ctx;
    int ret;
    uint32_t bytes_sent = 0;
    uint32_t chunk_size = 0;
    uint32_t data_counter = 0;
    uint32_t percentage;
    uint32_t fpt_size = 0;
    const uint8_t *fpt_data = NULL;
    uint32_t partition;
    struct gsc_fwu_heci_image_metadata meta;

    struct gsc_perf_cnt _perf_ctx;
    struct gsc_perf_cnt *perf_ctx = &_perf_ctx;

    if (handle == NULL || handle->ctx == NULL ||
        buffer == NULL || buffer_len == 0)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    partition = oprom_type_to_partition(oprom_type);
    if (partition == GSC_FWU_HECI_PART_VERSION_INVALID)
    {
        gsc_error("Bad oprom type %d\n", oprom_type);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (buffer_len > IGSC_MAX_IMAGE_SIZE)
    {
        gsc_error("Image size (%d) too big\n", buffer_len);
        return IGSC_ERROR_BAD_IMAGE;
    }

    lib_ctx = handle->ctx;

    gsc_pref_cnt_init(perf_ctx);
    gsc_pref_cnt_checkpoint(perf_ctx, "Program start");

    lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].content = buffer;
    lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size = buffer_len;

    /* OPROM image doesn't require meta data */
    meta.metadata_format_version = GSC_FWU_HECI_METADATA_VERSION_NONE;
    lib_ctx->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].content = (const uint8_t *)&meta;
    lib_ctx->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].size = sizeof(meta);

    fpt_size = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size;
    fpt_data = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].content;

    gsc_debug("Update Image Payload size: %d bytes\n", fpt_size);

    gsc_pref_cnt_checkpoint(perf_ctx, "After reading and parsing image");

    ret = driver_init(lib_ctx);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "Before FWU_START");

    ret = gsc_fwu_start(lib_ctx, partition);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After FWU_START");

    while (bytes_sent < fpt_size)
    {
        if (get_percentage(lib_ctx, &percentage) == IGSC_SUCCESS)
        {
            if (progress_f)
            {
                progress_f(percentage, 100, ctx);
            }
        }

        chunk_size = gsc_fwu_chunk_size(lib_ctx, fpt_size - bytes_sent);
        ret = gsc_fwu_data(lib_ctx, fpt_data + bytes_sent, chunk_size);
        if (ret != IGSC_SUCCESS)
        {
            goto exit;
        }
        bytes_sent += chunk_size;
        data_counter++;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After FWU_DATA");

    gsc_debug("Update Image sent to FW via %d FWU_DATA messages\n",
              data_counter);

    ret = gsc_fwu_end(lib_ctx);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After FWU_END");

    while (gsc_fwu_is_in_progress(lib_ctx))
    {
        if (get_percentage(lib_ctx, &percentage) == IGSC_SUCCESS)
        {
            if (progress_f)
            {
                progress_f(percentage, 100, ctx);
            }
        }
        else
        {
            gsc_msleep(100);
        }
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After PLRs");

    driver_reconnect(lib_ctx);

exit:
    gsc_fwu_img_layout_reset(&lib_ctx->layout);

    driver_deinit(lib_ctx);

    return ret;
}
