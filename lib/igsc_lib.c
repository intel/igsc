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
#include "gcc/config.h"

#include "igsc_system.h"
#include "igsc_heci.h"

#include <metee.h>

#include "igsc_lib.h"
#include "igsc_oprom.h"
#include "igsc_perf.h"
#include "igsc_log.h"
#include "igsc_internal.h"

#include "utils.h"

DEFINE_GUID(GUID_METEE_FWU, 0x87d90ca5, 0x3495, 0x4559,
            0x81, 0x05, 0x3f, 0xbf, 0xa3, 0x7b, 0x8b, 0x79);

enum gsc_dg2_sku_id {
    GSC_DG2_SKUID_512 = 0,
    GSC_DG2_SKUID_128 = 1,
    GSC_DG2_SKUID_256 = 2
};

enum gsc_soc_step_id {
    GSC_SOC_STEP_A0_ID      = 0x0,
    GSC_SOC_STEP_A1_ID      = 0x1,
    GSC_SOC_STEP_B0_ID      = 0x2,
    GSC_SOC_STEP_INVALID_ID = 0xFF
};


struct gsc_hw_config_1 {
    uint32_t hw_sku;
    uint32_t hw_step;
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

#if defined(DEBUG) || defined(_DEBUG)
static void gsc_debug_hex_dump(const char *title, const void *buf, size_t len)
{
#define pbufsz (16 * 3)
    char pbuf[pbufsz];
    const unsigned char *_buf = buf;
    size_t j = 0;

    debug_print("%s\n", title);

    while (len-- > 0)
    {
        snprintf(&pbuf[j], pbufsz - j, "%02X ", *_buf++);
        j += 3;
        if (j == 16 * 3)
        {
            debug_print("%s\n", pbuf);
            j = 0;
        }
    }
    if (j)
    {
        debug_print("%s\n", pbuf);
    }
}
#else
static void gsc_debug_hex_dump(const char *title, const void *buf, size_t len)
{
    (void)title; /* unused */
    (void)buf;   /* unused */
    (void)len;   /* unused */
}
#endif /* defined(DEBUG) || defined(_DEBUG) */

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

mockable
void gsc_driver_deinit(struct igsc_lib_ctx *lib_ctx)
{
    if (!lib_ctx->driver_init_called)
    {
        return;
    }

    driver_working_buffer_free(lib_ctx);

    TeeDisconnect(&lib_ctx->driver_handle);

    lib_ctx->driver_init_called = false;
}

mockable
int gsc_driver_init(struct igsc_lib_ctx *lib_ctx, IN const GUID *guid)
{
    TEESTATUS tee_status;
    int status;

    if (lib_ctx->dev_handle == IGSC_INVALID_DEVICE_HANDLE)
    {
        tee_status = TeeInit(&lib_ctx->driver_handle, guid, lib_ctx->device_path);
    }
    else
    {
        tee_status = TeeInitHandle(&lib_ctx->driver_handle, guid, lib_ctx->dev_handle);
    }

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

#define RECONNECT_ITERATIONS  10
#define RECONNECT_TIMEOUT    100

static int driver_reconnect(struct igsc_lib_ctx *lib_ctx)
{
    TEESTATUS tee_status;
    int status;
    uint32_t counter = 0;

    for (counter = 0; counter < RECONNECT_ITERATIONS; counter++)
    {
        tee_status = TeeConnect(&lib_ctx->driver_handle);
        if (TEE_IS_SUCCESS(tee_status))
        {
            break;
        }
        gsc_msleep(RECONNECT_TIMEOUT);
    }

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

    /**
     * Note: that only INFO and FWIM sections MUST appear in the image,
     * while IMGI section is optional.
     * */
    if (fpt->header.num_of_entries < FWU_FPT_ENTRY_IMAGE_INSTANCE ||
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
            case IMGI_HEADER_MARKER:
                entry_id = FWU_FPT_ENTRY_IMAGE_INSTANCE;
                break;
            default:
                entry_id = FWU_FPT_ENTRY_NUM;
                break;
        }

        if (entry_id == FWU_FPT_ENTRY_NUM)
        {
            continue;
        }

        if (entries_found_bitmask & BIT(entry_id))
        {
            gsc_error("FPT entry 0x%x already encountered\n",
                      entry->partition_name);
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }

        entries_found_bitmask |= BIT(entry_id);

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

int gsc_fwu_buffer_validate(struct igsc_lib_ctx *lib_ctx,
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

static int gsc_fwu_heci_validate_response_header(struct igsc_lib_ctx *lib_ctx,
                                                 struct gsc_fwu_heci_response *resp_header,
                                                 enum gsc_fwu_heci_command_id command_id)
{
    int status;

    if (resp_header == NULL)
    {
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    lib_ctx->last_firmware_status = resp_header->status;

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

mockable
int gsc_tee_command(struct igsc_lib_ctx *lib_ctx,
                    void *req_buf, size_t request_len,
                    void *resp_buf, size_t buf_size,
                    size_t *response_len)
{
    size_t num_bytes;
    int status;
    TEESTATUS tee_status;

    gsc_debug_hex_dump("Sending:", req_buf, buf_size);

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

    gsc_debug_hex_dump("Received:", resp_buf, *response_len);

    status = IGSC_SUCCESS;

exit:
    return status;
}

static int gsc_send_no_update(struct igsc_lib_ctx *lib_ctx)
{
    TEESTATUS tee_status;
    int status;
    size_t request_len;
    struct gsc_fwu_heci_no_update_req *req;

    req = (struct gsc_fwu_heci_no_update_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, 0);
    if (status != IGSC_SUCCESS)
    {
        return status;
    }

    memset(req, 0, request_len);
    req->header.command_id = GSC_FWU_HECI_COMMAND_ID_NO_UPDATE;
    req->reserved = 0;

    gsc_debug_hex_dump("Sending:", (unsigned char *)req, request_len);

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

static int gsc_fwu_get_version(struct igsc_lib_ctx *lib_ctx,
                               uint32_t partition,
                               uint8_t *version, size_t version_length)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len;

    struct gsc_fwu_heci_version_resp *resp;
    struct gsc_fwu_heci_version_req *req;
    uint8_t command_id = GSC_FWU_HECI_COMMAND_ID_GET_IP_VERSION;

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

    status = gsc_fwu_heci_validate_response_header(lib_ctx, &resp->response, command_id);
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

    if (gsc_memcpy_s(version, version_length,
                     resp->version, resp->version_length))
    {
        gsc_error("Copy of version data failed\n");
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}

static int gsc_get_fw_version(struct igsc_lib_ctx *lib_ctx,
                              struct igsc_fw_version *version)
{
    return gsc_fwu_get_version(lib_ctx, GSC_FWU_HECI_PART_VERSION_GFX_FW,
                               (uint8_t *)version, sizeof(*version));
}

static int gsc_fwu_get_oprom_version(struct igsc_lib_ctx *lib_ctx,
                                     uint32_t partition,
                                     struct igsc_oprom_version *version)
{
    return gsc_fwu_get_version(lib_ctx, partition,
                               (uint8_t *)version, sizeof(*version));
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
    struct gsc_fwu_heci_image_metadata zero_meta_data = {0};

    struct gsc_fwu_heci_start_req  *req;
    struct gsc_fwu_heci_start_resp *resp;
    uint8_t command_id = GSC_FWU_HECI_COMMAND_ID_START;

    req = (struct gsc_fwu_heci_start_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gsc_fwu_heci_start_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_IAF_PSC)
    {
        fpt_info_len = sizeof(zero_meta_data);
        fpt_info = (const uint8_t *)&zero_meta_data;
    }
    else
    {
        fpt_info_len = lib_ctx->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].size;
        fpt_info = lib_ctx->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].content;
    }
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
        gsc_error("Copy of meta data failed, buf len %ld meta data len %u\n",
                  buf_len - sizeof(*req), fpt_info_len);
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

    status = gsc_fwu_heci_validate_response_header(lib_ctx, &resp->response, command_id);
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
    uint8_t command_id = GSC_FWU_HECI_COMMAND_ID_DATA;

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

    status = gsc_fwu_heci_validate_response_header(lib_ctx, &resp->response, command_id);
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
    uint8_t command_id = GSC_FWU_HECI_COMMAND_ID_END;

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

    gsc_debug_hex_dump("Sending:", (unsigned char *)req, request_len);

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

    init_completed = !!(value & HECI1_CSE_FS_INITSTATE_COMPLETED_BIT);
    fu_idle = !(value & HECI1_CSE_FS_FWUPDATE_STATE_IDLE_BIT);

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

    fwsts_phase = (value >> HECI1_CSE_FS_FWUPD_PHASE_SHIFT) &
                  HECI1_CSE_FS_FWUPD_PHASE_MASK;
    fwsts_value = (value >> HECI1_CSE_FS_FWUPD_PERCENT_SHIFT) &
                  HECI1_CSE_FS_FWUPD_PERCENT_MASK;

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
    handle->ctx->dev_handle = IGSC_INVALID_DEVICE_HANDLE;

    handle->ctx->device_path = igsc_strdup(device_path);
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
    if (handle == NULL || dev_handle == IGSC_INVALID_DEVICE_HANDLE)
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
    handle->ctx->dev_handle = dev_handle;

    return IGSC_SUCCESS;
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

int igsc_device_get_device_info(IN  struct igsc_device_handle *handle,
                                OUT struct igsc_device_info *dev_info)
{
    if (handle == NULL || dev_info == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (handle->ctx == NULL || handle->ctx->device_path == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return get_device_info_by_devpath(handle->ctx->device_path, dev_info);
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
    ret = gsc_driver_init(lib_ctx, &GUID_METEE_FWU);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to init HECI driver\n");
        return ret;
    }

    ret = gsc_get_fw_version(lib_ctx, version);

    gsc_driver_deinit(lib_ctx);

    return ret;
}

static int gsc_device_hw_config(struct igsc_lib_ctx *lib_ctx,
                                struct igsc_hw_config *hw_config)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len;
    size_t buf_len;
    struct gsc_hw_config_1 *hw_config_1;

    struct gsc_fwu_heci_get_config_message_resp *resp;
    struct gsc_fwu_heci_get_config_message_req *req;
    uint8_t command_id = GSC_FWU_HECI_COMMAND_ID_GET_CONFIG;

    if (hw_config == NULL)
    {
        gsc_error("Invalid parameter\n");
        return IGSC_ERROR_INTERNAL;
    }

    memset(hw_config, 0, sizeof(*hw_config));
    hw_config_1 = (struct gsc_hw_config_1 *)hw_config->blob;

    req = (struct gsc_fwu_heci_get_config_message_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gsc_fwu_heci_get_config_message_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Buffer validation failed\n");
        return status;
    }

    memset(req, 0, request_len);
    req->header.command_id = command_id;

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

    status = gsc_fwu_heci_validate_response_header(lib_ctx, &resp->response, command_id);
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

    gsc_debug("HW Config: fmt %u hw step %u, hw sku %u debug_config %u\n",
              resp->format_version,
              resp->hw_step, resp->hw_sku,
              resp->debug_config);

    if (resp->format_version != GSC_FWU_GET_CONFIG_FORMAT_VERSION)
    {
        gsc_error("Got wrong message GET_CONFIG_FORMAT_VERSION (%u) while expecting (%u)\n",
                  resp->format_version, GSC_FWU_GET_CONFIG_FORMAT_VERSION);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    hw_config->format_version = resp->format_version;
    hw_config_1->hw_step = resp->hw_step;

    /* convert to firmware bit mask for easier comparison */
    if (resp->hw_step == GSC_DG2_SKUID_512)
    {
        hw_config_1->hw_sku = GSC_IFWI_TAG_512_SKU_BIT;
    }
    else if (resp->hw_step == GSC_DG2_SKUID_256)
    {
        hw_config_1->hw_sku = GSC_IFWI_TAG_256_SKU_BIT;
    }
    else if (resp->hw_step == GSC_DG2_SKUID_128)
    {
        hw_config_1->hw_sku = GSC_IFWI_TAG_128_SKU_BIT;
    }
    else
    {
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = IGSC_SUCCESS;

exit:
    return status;
}

int igsc_device_hw_config(IN struct igsc_device_handle *handle,
                          OUT struct igsc_hw_config *hw_config)
{
    struct igsc_lib_ctx *lib_ctx;
    struct igsc_fw_version version;
    int ret;

    if (handle == NULL || handle->ctx == NULL || hw_config == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    memset(&version, 0, sizeof(version));
    memset(hw_config, 0, sizeof(*hw_config));

    lib_ctx = handle->ctx;
    ret = gsc_driver_init(lib_ctx, &GUID_METEE_FWU);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to init HECI driver\n");
        return ret;
    }

    ret = gsc_get_fw_version(lib_ctx, &version);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to retrieve firmware version %d\n", ret);
        goto exit;
    }

    /* the command is only supported on DG2 */
    if (memcmp(version.project, "DG02", sizeof(version.project)))
    {
        ret = IGSC_ERROR_NOT_SUPPORTED;
        goto exit;
    }

    ret = gsc_device_hw_config(lib_ctx, hw_config);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to retrieve hardware config %d\n", ret);
    }

exit:
    gsc_driver_deinit(lib_ctx);

    return ret;
}

static int gsc_image_fw_version(IN const struct gsc_fwu_img_layout *layout,
                                 OUT struct igsc_fw_version *version)
{
    struct gsc_fwu_heci_image_metadata *meta;
    struct gsc_fwu_image_metadata_v1 *meta_v1;
    uint32_t meta_len;

    meta = (struct gsc_fwu_heci_image_metadata *)layout->table[FWU_FPT_ENTRY_IMAGE_INFO].content;
    meta_len = layout->table[FWU_FPT_ENTRY_IMAGE_INFO].size;

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

    if (gsc_memcpy_s(version, sizeof(*version),
                     &meta_v1->overall_version, sizeof(meta_v1->overall_version)))
    {
        gsc_error("Copy of version data failed\n");
        return IGSC_ERROR_INTERNAL;
    }

    return IGSC_SUCCESS;
}

int igsc_image_fw_version(IN  const uint8_t *buffer,
                          IN  uint32_t buffer_len,
                          OUT struct igsc_fw_version *version)
{
    int    ret;
    struct gsc_fwu_img_layout layout;

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

    return gsc_image_fw_version(&layout, version);
}

static int gsc_image_hw_config(const struct gsc_fwu_img_layout *layout,
                               struct igsc_hw_config *hw_config)
{
    struct fwu_gws_image_info *info = NULL;
    struct gsc_hw_config_1 *hw_config_1;
    uint32_t info_len;


    info = (struct fwu_gws_image_info *)layout->table[FWU_FPT_ENTRY_IMAGE_INSTANCE].content;
    info_len = layout->table[FWU_FPT_ENTRY_IMAGE_INSTANCE].size;

    if (info_len < sizeof(*info))
    {
        gsc_error("No valid IMGI section in the image\n");
        return IGSC_ERROR_BAD_IMAGE;
    }

    if (info->format_version != FWU_GWS_IMAGE_INFO_FORMAT_VERSION)
    {
        gsc_error("Wrong Image Info format version in the Image, got %u, expected %u\n",
                  info->format_version, FWU_GWS_IMAGE_INFO_FORMAT_VERSION);
        return IGSC_ERROR_BAD_IMAGE;
    }

    gsc_debug("Image Instance Id 0x%x\n", info->instance_id);

    hw_config->format_version = info->format_version;
    hw_config_1 = (struct gsc_hw_config_1 *)hw_config->blob;
    hw_config_1->hw_sku = info->instance_id;
    hw_config_1->hw_step = 0;

    return IGSC_SUCCESS;
}

int igsc_image_hw_config(IN  const uint8_t *buffer,
                         IN  uint32_t buffer_len,
                         OUT struct igsc_hw_config *hw_config)
{
    int    ret;
    struct gsc_fwu_img_layout layout;
    struct igsc_fw_version version;

    if (buffer == NULL || buffer_len == 0 || hw_config == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    memset(&version, 0, sizeof(version));
    memset(hw_config, 0, sizeof(*hw_config));

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

    ret = gsc_image_fw_version(&layout, &version);

    /* the command is only supported on DG2 */
    if (memcmp(version.project, "DG02", sizeof(version.project)))
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    return gsc_image_hw_config(&layout, hw_config);
}

int igsc_image_get_type(IN const uint8_t *buffer,
                        IN const uint32_t buffer_len,
                        OUT uint8_t *type)
{
    struct gsc_fwu_img_layout layout;
    struct igsc_oprom_image *oimg = NULL;
    int ret;
    uint8_t img_type = IGSC_IMAGE_TYPE_UNKNOWN;
    uint32_t oimg_type;

    if (type == NULL || buffer == NULL || buffer_len == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    gsc_fwu_img_layout_reset(&layout);

    ret = gsc_fwu_img_layout_parse(&layout, buffer, buffer_len);
    if (ret == IGSC_SUCCESS)
    {
        img_type = IGSC_IMAGE_TYPE_GFX_FW;
        goto exit;
    }

    ret = igsc_image_oprom_init(&oimg, buffer, buffer_len);
    if (ret == IGSC_SUCCESS)
    {
        ret = igsc_image_oprom_type(oimg, &oimg_type);
        if (ret == IGSC_SUCCESS)
        {
             if (oimg_type == IGSC_OPROM_DATA)
             {
                 img_type = IGSC_IMAGE_TYPE_OPROM_DATA;
                 goto exit;
             }
             else if (oimg_type == IGSC_OPROM_CODE)
             {
                 img_type = IGSC_IMAGE_TYPE_OPROM_CODE;
                 goto exit;
             }
             else if (oimg_type == (IGSC_OPROM_DATA | IGSC_OPROM_CODE))
             {
                 img_type = IGSC_IMAGE_TYPE_OPROM;
                 goto exit;
             }
        }
        ret = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    ret = IGSC_ERROR_BAD_IMAGE;

exit:
    gsc_fwu_img_layout_reset(&layout);

    igsc_image_oprom_release(oimg);

    *type = img_type;

    return ret;
}

static int gsc_update(IN struct igsc_device_handle *handle,
                      IN const void *buffer,
                      IN const uint32_t buffer_len,
                      IN igsc_progress_func_t progress_f,
                      IN void *ctx,
                      IN uint32_t payload_type)
{
    struct igsc_lib_ctx *lib_ctx;
    int      ret;
    uint32_t bytes_sent = 0;
    uint32_t chunk_size = 0;
    uint32_t data_counter = 0;
    uint32_t percentage = 0;
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

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW)
    {
        ret = gsc_fwu_img_layout_parse(&lib_ctx->layout, buffer, buffer_len);
        if (ret != IGSC_SUCCESS)
        {
            goto exit;
        }
    }
    else if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_IAF_PSC)
    {
        lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size = buffer_len;
        lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].content = buffer;
    }
    else
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    fpt_size = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size;
    fpt_data = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].content;


    gsc_debug("Update Image Payload size: %d bytes\n", fpt_size);

    gsc_pref_cnt_checkpoint(perf_ctx, "After reading and parsing image");

    ret = gsc_driver_init(lib_ctx, &GUID_METEE_FWU);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "Before FWU_START");

    ret = gsc_fwu_start(lib_ctx, payload_type);
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

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW)
    {
    /* In order for the underlying library to detect the firmware reset
     * and to update its state for the current handle a dummy command
     * (get fw version) needs to be performed. The expectation is
     * that it will fail eventually.
     */
        #define MAX_GET_VERSION_RETRIES 20
        struct igsc_fw_version version;
        unsigned int i;
        for (i = 0; i < MAX_GET_VERSION_RETRIES; i++)
        {
            if (gsc_get_fw_version(lib_ctx, &version) != IGSC_SUCCESS)
            {
               break;
            }
            gsc_msleep(100);
        }
    }

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
    /*
     * In the case that the actual update was completed
     * between the fwu_end message and the progress
     * check gsc_fwu_is_in_progress() the progress_f(100)
     * needs to be called explicitly to announce the completion.
     */
    if (percentage != 100)
    {
         if (progress_f)
         {
             progress_f(100, 100, ctx);
         }
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After PLRs");

    /*
     * After Gfx FW update there is a FW reset so driver reconnect is needed
     */
    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW)
    {
        ret = driver_reconnect(lib_ctx);

        if (ret == IGSC_SUCCESS)
        {
            /* After the reconnect - send 'no update' message */
            ret = gsc_send_no_update(lib_ctx);
            if (ret != IGSC_SUCCESS)
            {
               gsc_error("failed to send 'no update' message after reset\n");
            }
        }
        else
        {
            gsc_error("failed to reconnect to the driver after reset\n");
        }
    }

exit:

    gsc_fwu_img_layout_reset(&lib_ctx->layout);

    gsc_driver_deinit(lib_ctx);

    return ret;
}

int igsc_device_fw_update(IN struct igsc_device_handle *handle,
                          IN const uint8_t *buffer,
                          IN const uint32_t buffer_len,
                          IN igsc_progress_func_t progress_f,
                          IN void *ctx)
{
    return gsc_update(handle, buffer, buffer_len, progress_f, ctx,
                      GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW);
}

int igsc_iaf_psc_update(IN struct igsc_device_handle *handle,
                        IN const uint8_t *buffer,
                        IN const uint32_t buffer_len,
                        IN igsc_progress_func_t progress_f,
                        IN void *ctx)
{
    return gsc_update(handle, buffer, buffer_len, progress_f, ctx,
                      GSC_FWU_HECI_PAYLOAD_TYPE_IAF_PSC);
}

uint8_t igsc_fw_version_compare(IN struct igsc_fw_version *image_version,
                                IN struct igsc_fw_version *device_version)
{

    if (image_version == NULL || device_version == NULL)
    {
        return IGSC_VERSION_ERROR;
    }

    if (memcmp(image_version->project, device_version->project,
               sizeof(image_version->project)))
    {
        return IGSC_VERSION_NOT_COMPATIBLE;
    }

    if (image_version->hotfix < device_version->hotfix)
        return IGSC_VERSION_OLDER;

    if (image_version->hotfix > device_version->hotfix)
        return IGSC_VERSION_NEWER;

    if (image_version->build < device_version->build)
       return IGSC_VERSION_OLDER;

    if (image_version->build > device_version->build)
       return IGSC_VERSION_NEWER;

    return IGSC_VERSION_EQUAL;
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
    ret = gsc_driver_init(lib_ctx, &GUID_METEE_FWU);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to init HECI driver\n");
        return ret;
    }

    ret = gsc_fwu_get_oprom_version(lib_ctx, partition, version);

    gsc_driver_deinit(lib_ctx);

    return ret;
}

static int igsc_oprom_update_from_buffer(IN  struct igsc_device_handle *handle,
                                         IN  uint32_t oprom_type,
                                         IN  const uint8_t *buffer,
                                         IN  size_t buffer_len,
                                         IN  igsc_progress_func_t progress_f,
                                         IN  void *ctx)
{
    struct igsc_lib_ctx *lib_ctx;
    int ret;
    uint32_t bytes_sent = 0;
    uint32_t chunk_size = 0;
    uint32_t data_counter = 0;
    uint32_t percentage = 0;
    uint32_t fpt_size = 0;
    const uint8_t *fpt_data = NULL;
    uint32_t partition;
    struct gsc_fwu_heci_image_metadata meta;

    struct gsc_perf_cnt _perf_ctx;
    struct gsc_perf_cnt *perf_ctx = &_perf_ctx;

    if (handle == NULL || handle->ctx == NULL || buffer == NULL)
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

    gsc_pref_cnt_init(perf_ctx);
    gsc_pref_cnt_checkpoint(perf_ctx, "Program start");

    lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].content = buffer;
    lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size = (uint32_t)buffer_len;

    /* OPROM image doesn't require meta data */
    meta.metadata_format_version = GSC_FWU_HECI_METADATA_VERSION_NONE;
    lib_ctx->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].content = (const uint8_t *)&meta;
    lib_ctx->layout.table[FWU_FPT_ENTRY_IMAGE_INFO].size = sizeof(meta);

    fpt_size = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size;
    fpt_data = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].content;

    gsc_debug("Update Image Payload size: %d bytes\n", fpt_size);

    gsc_pref_cnt_checkpoint(perf_ctx, "After reading and parsing image");

    ret = gsc_driver_init(lib_ctx, &GUID_METEE_FWU);
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

    /*
     * In the case that the actual update was completed
     * between the fwu_end message and the progress
     * check gsc_fwu_is_in_progress() the progress_f(100)
     * needs to be called explicitly to announce the completion.
     */
    if (percentage != 100)
    {
         if (progress_f)
         {
             progress_f(100, 100, ctx);
         }
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After PLRs");

exit:
    gsc_fwu_img_layout_reset(&lib_ctx->layout);

    gsc_driver_deinit(lib_ctx);

    return ret;
}

int igsc_device_oprom_update(IN  struct igsc_device_handle *handle,
                             IN  uint32_t oprom_type,
                             IN  struct igsc_oprom_image *img,
                             IN  igsc_progress_func_t progress_f,
                             IN  void *ctx)
{
    int ret;
    const uint8_t *buffer = NULL;
    size_t buffer_len;

    ret = image_oprom_get_buffer(img, oprom_type, &buffer, &buffer_len);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    if (buffer == NULL || buffer_len == 0 || buffer_len > IGSC_MAX_IMAGE_SIZE)
    {
        gsc_error("Image size (%zd) too big\n", buffer_len);
        return IGSC_ERROR_BAD_IMAGE;
    }

    return igsc_oprom_update_from_buffer(handle, oprom_type, buffer, buffer_len,
                                         progress_f, ctx);
}

uint32_t igsc_get_last_firmware_status(IN  struct igsc_device_handle *handle)
{
    return handle->ctx->last_firmware_status;
}

const char *igsc_translate_firmware_status(IN  uint32_t firmware_status)
{
    const char *msg = NULL;

    switch (firmware_status) {
    case GSC_FWU_STATUS_SUCCESS:
        msg = "Success";
        break;
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

    return msg;
}
