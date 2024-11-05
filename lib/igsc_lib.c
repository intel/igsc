/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2024 Intel Corporation
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

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
#include "fw_data_parser.h"

#include "utils.h"

#define TEE_WRITE_TIMEOUT 60000 /* 60 sec */
#define TEE_READ_TIMEOUT  480000 /* 480 sec */

DEFINE_GUID(GUID_METEE_FWU, 0x87d90ca5, 0x3495, 0x4559,
            0x81, 0x05, 0x3f, 0xbf, 0xa3, 0x7b, 0x8b, 0x79);

enum gsc_sku_id {
    GSC_SKUID_SOC1 = 0,
    GSC_SKUID_SOC2 = 1,
    GSC_SKUID_SOC3 = 2,
    GSC_SKUID_SOC4 = 3
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
    uint32_t oprom_code_devid_enforcement : 1;
    uint32_t flags                        : 31;
    uint32_t debug_config;
};

#define to_hw_config_1(cfg) ((struct gsc_hw_config_1 *)(cfg)->blob)

DEFINE_GUID(GUID_METEE_MCHI, 0xfe2af7a6, 0xef22, 0x4b45,
            0x87, 0x2f, 0x17, 0x6b, 0xb, 0xbc, 0x8b, 0x43);

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
    case TEE_TIMEOUT:
        return IGSC_ERROR_TIMEOUT;
    case TEE_PERMISSION_DENIED:
        return IGSC_ERROR_PERMISSION_DENIED;
    default:
        return IGSC_ERROR_INTERNAL;
    }
}

static void __gsc_trace_hex_dump(const char *title, const void *buf, size_t len)
{
#define pbufsz (16 * 3)
    char pbuf[pbufsz];
    const unsigned char *_buf = buf;
    size_t j = 0;

    trace_print("%s\n", title);

    while (len-- > 0)
    {
        snprintf(&pbuf[j], pbufsz - j, "%02X ", *_buf++);
        j += 3;
        if (j == 16 * 3)
        {
            trace_print("%s\n", pbuf);
            j = 0;
        }
    }
    if (j)
    {
        trace_print("%s\n", pbuf);
    }
}

static inline void gsc_trace_hex_dump(const char* title, const void* buf, size_t len)
{
    if (igsc_get_log_level() >= IGSC_LOG_LEVEL_TRACE)
        __gsc_trace_hex_dump(title, buf, len);
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

mockable
void gsc_driver_deinit(struct igsc_lib_ctx *lib_ctx)
{
    if (!lib_ctx->driver_init_called)
    {
        return;
    }

    if (lib_ctx->restore_power_control)
    {
        if (gsc_set_device_power_control(lib_ctx->device_path, GSC_POWER_CONTROL_AUTO) == IGSC_SUCCESS)
        {
             gsc_debug("restored power control to 'auto' for %s\n", lib_ctx->device_path);
             lib_ctx->restore_power_control = false;
        }
    }

    driver_working_buffer_free(lib_ctx);

    TeeDisconnect(&lib_ctx->driver_handle);

    lib_ctx->driver_init_called = false;
}

void gsc_metee_log(bool is_error, const char* fmt, ...)
{
    UNUSED_VAR(is_error);
#define DEBUG_MSG_LEN 1024
    char msg[DEBUG_MSG_LEN];
    va_list varl;
    va_start(varl, fmt);
    vsnprintf(msg, DEBUG_MSG_LEN, fmt, varl);
    va_end(varl);
    printf("%s\n", msg);
}

#define INIT_ITERATIONS  3
#define INIT_TIMEOUT 1000

mockable
int gsc_driver_init(struct igsc_lib_ctx *lib_ctx, IN const GUID *guid)
{
    TEESTATUS tee_status;
    int status;
    uint8_t power_control;
    uint32_t counter = 0;
    unsigned int igsc_log_level;
    unsigned int tee_log_level = TEE_LOG_LEVEL_ERROR;

    for (counter = 0; counter < INIT_ITERATIONS; counter++)
    {
        if (lib_ctx->dev_handle == IGSC_INVALID_DEVICE_HANDLE)
        {
            tee_status = TeeInit(&lib_ctx->driver_handle, guid, lib_ctx->device_path);
        }
        else
        {
            tee_status = TeeInitHandle(&lib_ctx->driver_handle, guid, lib_ctx->dev_handle);
        }
        if (tee_status != TEE_DEVICE_NOT_READY)
        {
            break;
        }
        gsc_debug("HECI init - device is not ready, retrying...\n");
        gsc_msleep(INIT_TIMEOUT);
    }

    if (!TEE_IS_SUCCESS(tee_status))
    {
        gsc_error("Error in HECI init (%d)\n", tee_status);
        status = status_tee2fu(tee_status);
        goto exit;
    }

    igsc_log_level = igsc_get_log_level();
    if (igsc_log_level >= IGSC_LOG_LEVEL_DEBUG)
    {
        tee_log_level = TEE_LOG_LEVEL_VERBOSE;
    }
    TeeSetLogLevel(&lib_ctx->driver_handle, tee_log_level);
    TeeSetLogCallback(&lib_ctx->driver_handle, gsc_metee_log);

    tee_status = TeeConnect(&lib_ctx->driver_handle);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        TeeDisconnect(&lib_ctx->driver_handle);
        gsc_error("Error in HECI connect (%d)\n", tee_status);
        /**
         * Special case for connect - igsc library should propagate the
         * TEE_BUSY error (in Linux) and TEE_UNABLE_TO_COMPLETE_OPERATION (in Win)
         * as IGSC_ERROR_BUSY to the caller , only for the Connect failures,
         * because in other operations those errors mean something else,
         * not that someone has taken the client's handle
         **/
        if (tee_status == TEE_BUSY || tee_status == TEE_UNABLE_TO_COMPLETE_OPERATION)
            status = IGSC_ERROR_BUSY;
        else
            status = status_tee2fu(tee_status);
        goto exit;
    }

    status = driver_working_buffer_alloc(lib_ctx);
    if (status != IGSC_SUCCESS)
    {
        TeeDisconnect(&lib_ctx->driver_handle);
        goto exit;
    }

    if (gsc_get_device_power_control(lib_ctx->device_path, &power_control) == IGSC_SUCCESS &&
        power_control != GSC_POWER_CONTROL_ON)
    {
        if (gsc_set_device_power_control(lib_ctx->device_path, GSC_POWER_CONTROL_ON) == IGSC_SUCCESS)
        {
            gsc_debug("set power control to 'on' for %s\n", lib_ctx->device_path);
            lib_ctx->restore_power_control = true;
        }
    }

    lib_ctx->driver_init_called = true;

    status = IGSC_SUCCESS;

exit:
    return status;
}

#ifdef _DEBUG
static void gsc_suppress_errors(struct igsc_lib_ctx *lib_ctx)
{
    (void)lib_ctx;
    return;
}

static void gsc_unsuppress_errors(struct igsc_lib_ctx *lib_ctx)
{
    (void)lib_ctx;
    return;
}
#else
static void gsc_suppress_errors(struct igsc_lib_ctx *lib_ctx)
{
    lib_ctx->suppress_errors = true;

    lib_ctx->tee_prev_log_level = TeeSetLogLevel(&lib_ctx->driver_handle, TEE_LOG_LEVEL_QUIET);

}

static void gsc_unsuppress_errors(struct igsc_lib_ctx *lib_ctx)
{
    lib_ctx->suppress_errors = false;

    TeeSetLogLevel(&lib_ctx->driver_handle, lib_ctx->tee_prev_log_level);
}
#endif

static bool gsc_errors_suppressed(struct igsc_lib_ctx *lib_ctx)
{
    return lib_ctx->suppress_errors;
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
        gsc_debug("Error in HECI connect (%d)\n", tee_status);
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
                                    const uint8_t *buffer, uint32_t buffer_len, uint32_t payload_type)
{
    int status;
    uint32_t i;
    uint32_t entries_found_bitmask = 0;
    size_t total_size;
    const struct gsc_fwu_fpt_img *fpt;

    if (buffer_len < sizeof(fpt->header))
    {
        gsc_error("Image size (%u) too small to contain FPT Header\n",
                buffer_len);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    if (buffer_len > IGSC_MAX_IMAGE_SIZE)
    {
        gsc_error("Image size (%u) too big\n", buffer_len);
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
        gsc_error("Invalid FPT number of entries (%u)\n",
                fpt->header.num_of_entries);
        status = IGSC_ERROR_BAD_IMAGE;
        goto exit;
    }

    total_size = sizeof(fpt->header) +
                 fpt->header.num_of_entries * sizeof(struct gsc_fwu_fpt_entry);

    if (buffer_len < total_size)
    {
        gsc_error("Image size (%u) can't hold %u entries\n",
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
            case SDTA_HEADER_MARKER:
                entry_id = FWU_FPT_ENTRY_FW_DATA_IMAGE;
                break;
            case CKSM_HEADER_MARKER:
                entry_id = FWU_FPT_ENTRY_CKSM;
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

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA)
    {
        if ((entries_found_bitmask & MANDATORY_FWDATA_ENTRY_BITMASK) != MANDATORY_FWDATA_ENTRY_BITMASK)
        {
            gsc_error("Mandatory FPT entries missing from update image\n");
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }
    }
    else
    {
        if ((entries_found_bitmask & MANDATORY_ENTRY_BITMASK) != MANDATORY_ENTRY_BITMASK)
        {
            gsc_error("Mandatory FPT entries missing from update image\n");
            status = IGSC_ERROR_BAD_IMAGE;
            goto exit;
        }
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
        gsc_error("Invalid command ID (%d)\n",
                resp_header->header.command_id);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->header.is_response != true)
    {
        gsc_error("HECI Response not marked as response\n");
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->status != GSC_FWU_STATUS_SUCCESS)
    {
        const char *msg = igsc_translate_firmware_status(resp_header->status);

        gsc_error("HECI message failed with status %s 0x%x\n",
                msg, resp_header->status);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->reserved != 0 || resp_header->header.reserved != 0 ||
        resp_header->header.reserved2[0] != 0 || resp_header->header.reserved2[1] != 0)
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

    gsc_trace_hex_dump("Sending:", req_buf, request_len);

    num_bytes = 0;
    tee_status = TeeWrite(&lib_ctx->driver_handle, req_buf, request_len, &num_bytes, TEE_WRITE_TIMEOUT);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        if (gsc_errors_suppressed(lib_ctx))
        {
            gsc_debug("Error in HECI write (%d)\n", tee_status);
        }
        else
        {
            gsc_error("Error in HECI write (%d)\n", tee_status);
        }
        status = status_tee2fu(tee_status);
        goto exit;
    }
    if (num_bytes != request_len)
    {
        gsc_error("Error in HECI write - bad size (%zu)\n", num_bytes);
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    tee_status = TeeRead(&lib_ctx->driver_handle, resp_buf, buf_size, response_len, TEE_READ_TIMEOUT);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        if (gsc_errors_suppressed(lib_ctx))
        {
            gsc_debug("Error in HECI read %d\n", tee_status);
        }
        else
        {
            gsc_error("Error in HECI read %d\n", tee_status);
        }
        status = status_tee2fu(tee_status);
        goto exit;
    }

    gsc_trace_hex_dump("Received:", resp_buf, *response_len);

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

    gsc_trace_hex_dump("Sending:", (unsigned char *)req, request_len);

    tee_status = TeeWrite(&lib_ctx->driver_handle, req, request_len, NULL, TEE_WRITE_TIMEOUT);
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
    size_t received_len = 0;
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
        gsc_debug("Invalid HECI message response (%d)\n", status);
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

static int gsc_fwu_start(struct igsc_lib_ctx *lib_ctx, uint32_t payload_type, bool force_update)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    const uint8_t *fpt_info;
    uint32_t fpt_info_len;
    struct gsc_fwu_heci_image_metadata zero_meta_data = {0};
    struct gsc_fwu_heci_start_flags flags = {0};

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

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA)
    {
        req->update_img_length = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].size;
    }
    else
    {
        req->update_img_length = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size;
    }
    req->payload_type = payload_type;

    if (force_update)
    {
        flags.force_update = 1;
    }
    req->flags = flags;

    memset(req->reserved, 0, sizeof(req->reserved));
    if (gsc_memcpy_s(&req->data, buf_len - sizeof(*req), fpt_info, fpt_info_len))
    {
        gsc_error("Copy of meta data failed, buf len %zu meta data len %u\n",
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
    size_t received_len = 0;
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

    gsc_trace_hex_dump("Sending:", (unsigned char *)req, request_len);

    tee_status = TeeWrite(&lib_ctx->driver_handle, req, request_len, NULL, TEE_WRITE_TIMEOUT);
    if (!TEE_IS_SUCCESS(tee_status))
    {
        /* There is a possible race condition in the heci driver between the ack for the write of
           fwu_end message and the firmware reset that happens in the firmware immediately after that.
           If the driver is slow it may cause a situation when the write ack interrupt and the reset
           interrupt are being processed together by the driver (in the same interrupt handler call)
           and so the driver would first look at the reset and decide that the write failed.
           So when sending fwu_end command, which as we know causes firmware reset by design, we do
           not check the return value of the write because it may be a failure as a result of this
           race condition described above.
         */
        gsc_debug("Error in HECI write (%d) on writing fwu_end message\n", tee_status);
    }

    status = IGSC_SUCCESS;

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

    uint32_t value = 0;

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

exit:
    return is_in_progress;
}

static bool gsc_fwu_is_finishing(struct igsc_lib_ctx *lib_ctx)
{
    int status;
    uint32_t value = 0;

    status = get_fwsts(lib_ctx, FWSTS(5), &value);
    if (status != IGSC_SUCCESS)
    {
        return true;
    }

    if (value & HECI1_CSE_FS_BACKGROUND_OPERATION_NEEDED_BIT)
    {
        return true;
    }

    return false;
}

static int get_percentage(struct igsc_lib_ctx *lib_ctx, uint32_t *percentage)
{
    int status;

    uint32_t value = 0;
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
    int ret;
    struct igsc_subsystem_ids ssids;

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

    ret = get_device_info_by_devpath(handle->ctx->device_path, dev_info);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    /* try to get the true subsystem vendor id and subsystem device id from the firmware */
    ret = igsc_device_subsystem_ids(handle, &ssids);
    if (ret != IGSC_SUCCESS)
    {
        /* can fail by design with legacy firmware, so return SUCCESS */
        return IGSC_SUCCESS;
    }
    gsc_debug("ssvid/ssdid PCI: %04x/%04x, FW: %04x/%04x\n",
              dev_info->subsys_vendor_id, dev_info->subsys_device_id,
              ssids.ssvid, ssids.ssdid);

    dev_info->subsys_device_id = ssids.ssdid;
    dev_info->subsys_vendor_id = ssids.ssvid;

    return ret;
}

int igsc_device_update_device_info(IN  struct igsc_device_handle *handle,
                                   OUT struct igsc_device_info *dev_info)
{
    struct igsc_subsystem_ids ssids;
    int ret;

    if (handle == NULL || dev_info == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    /* try to get the true subsystem vendor id and subsystem device id from the firmware */
    ret = igsc_device_subsystem_ids(handle, &ssids);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }
    gsc_debug("ssvid/ssdid PCI: %04x/%04x, FW: %04x/%04x\n",
              dev_info->subsys_vendor_id, dev_info->subsys_device_id,
              ssids.ssvid, ssids.ssdid);

    dev_info->subsys_device_id = ssids.ssdid;
    dev_info->subsys_vendor_id = ssids.ssvid;

    return ret;
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

static int gsc_device_subsystem_ids(struct igsc_lib_ctx  *lib_ctx,
                                    struct igsc_subsystem_ids *ids)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct gsc_fwu_heci_get_subsystem_ids_message_req  *req;
    struct gsc_fwu_heci_get_subsystem_ids_message_resp *resp;
    uint8_t command_id = GSC_FWU_HECI_COMMAND_ID_GET_SUBSYSTEM_IDS;

    if (ids == NULL)
    {
        gsc_error("Invalid parameter\n");
        return IGSC_ERROR_INTERNAL;
    }

    memset(ids, 0, sizeof(*ids));
    req = (struct gsc_fwu_heci_get_subsystem_ids_message_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gsc_fwu_heci_get_subsystem_ids_message_resp *)lib_ctx->working_buffer;
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
        gsc_debug("Invalid HECI message response (%d)\n", status);
        goto exit;
    }

    if (received_len != response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    gsc_debug("ssvid/ssdid 0x%04x/0x%04x\n", resp->ssvid, resp->ssdid);

    ids->ssvid = resp->ssvid;
    ids->ssdid = resp->ssdid;

    status = IGSC_SUCCESS;

exit:
    return status;

}

static int gsc_device_hw_config(struct igsc_lib_ctx *lib_ctx,
                                struct igsc_hw_config *hw_config)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
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

    /* Some platforms do not support hw_config command, it should not be treated as error */
    if (resp->response.status == GSC_FWU_STATUS_INVALID_COMMAND)
    {
        gsc_debug("Hw config command is not supported by the firmware\n");
        status = IGSC_ERROR_NOT_SUPPORTED;
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
    if (resp->hw_sku == GSC_SKUID_SOC1)
    {
        hw_config_1->hw_sku = GSC_IFWI_TAG_SOC1_SKU_BIT;
    }
    else if (resp->hw_sku == GSC_SKUID_SOC3)
    {
        hw_config_1->hw_sku = GSC_IFWI_TAG_SOC3_SKU_BIT;
    }
    else if (resp->hw_sku == GSC_SKUID_SOC2)
    {
        hw_config_1->hw_sku = GSC_IFWI_TAG_SOC2_SKU_BIT;
    }
    else if (resp->hw_sku == GSC_SKUID_SOC4)
    {
        hw_config_1->hw_sku = GSC_IFWI_TAG_SOC4_SKU_BIT;
    }
    else
    {
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    hw_config_1->oprom_code_devid_enforcement = resp->oprom_code_devid_enforcement;
    hw_config_1->flags = resp->flags;
    hw_config_1->debug_config = resp->debug_config;

    status = IGSC_SUCCESS;

exit:
    return status;
}

int igsc_device_subsystem_ids(IN struct  igsc_device_handle *handle,
                              OUT struct igsc_subsystem_ids *ssids)
{
    struct igsc_lib_ctx *lib_ctx;
    int ret;

    if (handle == NULL || handle->ctx == NULL || ssids == NULL)
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

    memset(ssids, 0, sizeof(*ssids));

    ret = gsc_device_subsystem_ids(lib_ctx, ssids);
    if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to retrieve subsystem ids: %d\n", ret);
    }

    gsc_driver_deinit(lib_ctx);

    return ret;
}

int igsc_device_hw_config(IN struct igsc_device_handle *handle,
                          OUT struct igsc_hw_config *hw_config)
{
    struct igsc_lib_ctx *lib_ctx;
    int ret;

    if (handle == NULL || handle->ctx == NULL || hw_config == NULL)
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

    memset(hw_config, 0, sizeof(*hw_config));

    ret = gsc_device_hw_config(lib_ctx, hw_config);
    if (ret == IGSC_ERROR_NOT_SUPPORTED)
    {
        /* some projects do not support get hw_config command, it's legal */
        gsc_debug("Getting hardware config is not supported by the firmware\n");
    }
    else if (ret != IGSC_SUCCESS)
    {
        gsc_error("Failed to retrieve hardware config %d\n", ret);
    }

    gsc_driver_deinit(lib_ctx);

    return ret;
}

int igsc_hw_config_to_string(IN const struct igsc_hw_config *hw_config,
                             IN char *buf, IN size_t length)
{
    int ret;
    int acc;

    if (hw_config == NULL  || buf == NULL || length == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    memset(buf, 0, length);

    if (hw_config->format_version == 0)
    {
         ret = snprintf(buf, length, "hw sku: [ n/a ] hw step: [ n/a ]");
         return ret;
    }

    if (to_hw_config_1(hw_config)->hw_sku == 0)
    {
        ret = snprintf(buf, length, "hw sku: [ n/a ]");
    }
    else
    {
        ret = snprintf(buf, length, "hw sku: [ %s%s%s%s]",
                       (GSC_IFWI_TAG_SOC1_SKU_BIT & to_hw_config_1(hw_config)->hw_sku) ? "SOC1 " : "",
                       (GSC_IFWI_TAG_SOC2_SKU_BIT & to_hw_config_1(hw_config)->hw_sku) ? "SOC2 " : "",
                       (GSC_IFWI_TAG_SOC3_SKU_BIT & to_hw_config_1(hw_config)->hw_sku) ? "SOC3 " : "",
                       (GSC_IFWI_TAG_SOC4_SKU_BIT & to_hw_config_1(hw_config)->hw_sku) ? "SOC4 " : "");
    }
    if (ret < 0)
    {
        return ret;
    }
    if ((size_t)ret >= length)
    {
        return ret;
    }

    buf += ret;
    length -= (size_t)ret;
    acc = ret;

    switch(to_hw_config_1(hw_config)->hw_step)
    {
    case GSC_SOC_STEP_A0_ID:
        ret = snprintf(buf, length, " hw step: [ A0 ]");
        break;
    case GSC_SOC_STEP_A1_ID:
        ret = snprintf(buf, length, " hw step: [ A1 ]");
        break;
    case GSC_SOC_STEP_B0_ID:
        ret = snprintf(buf, length, " hw step: [ B0 ]");
        break;
    case GSC_SOC_STEP_INVALID_ID:
    default:
        ret = snprintf(buf, length, " hw step: [ n/a ]");
    }

    if (ret < 0)
    {
        return ret;
    }
    if ((size_t)ret >= length)
    {
        return acc + (int)length;
    }

    buf += ret;
    length -= (size_t)ret;
    acc += ret;

    if (to_hw_config_1(hw_config)->oprom_code_devid_enforcement == 0)
    {
        ret = snprintf(buf, length, " oprom code device IDs check is not enforced");
    }
    else
    {
        ret = snprintf(buf, length, " oprom code device IDs check is enforced");
    }

    if (ret < 0)
    {
        return ret;
    }
    if ((size_t)ret >= length)
    {
        return acc + (int)length;
    }

    buf += ret;
    length -= (size_t)ret;
    acc += ret;

    ret = snprintf(buf, length, ", flags: 0x%04x", to_hw_config_1(hw_config)->flags);

    if (ret < 0)
    {
        return ret;
    }
    if ((size_t)ret >= length)
    {
        return acc + (int)length;
    }

    buf += ret;
    length -= (size_t)ret;
    acc += ret;

    ret = snprintf(buf, length, ", debug_config: 0x%04x", to_hw_config_1(hw_config)->debug_config);

    if (ret < 0)
    {
        return ret;
    }
    if ((size_t)ret >= length)
    {
        return acc + (int)length;
    }

    acc += ret;

    return acc;
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
    ret = gsc_fwu_img_layout_parse(&layout, buffer, buffer_len, GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW);
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
        /* Some images (like DG1) do not have IMGI section, this is legal */
        gsc_debug("No valid IMGI section in the image\n");
        return IGSC_ERROR_NOT_SUPPORTED;
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
    hw_config_1->oprom_code_devid_enforcement = 0;
    hw_config_1->flags = 0;
    hw_config_1->debug_config = 0;

    return IGSC_SUCCESS;
}

int igsc_image_oprom_code_devid_enforced(IN struct igsc_hw_config *hw_config, OUT bool *devid_enforced)
{
    struct gsc_hw_config_1 *hw_config_1;

    if (!hw_config || !devid_enforced)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    hw_config_1 = (struct gsc_hw_config_1 *)hw_config->blob;

    *devid_enforced = (hw_config_1->oprom_code_devid_enforcement == 1);

    return IGSC_SUCCESS;
}

int igsc_image_hw_config(IN  const uint8_t *buffer,
                         IN  uint32_t buffer_len,
                         OUT struct igsc_hw_config *hw_config)
{
    int    ret;
    struct gsc_fwu_img_layout layout;

    if (buffer == NULL || buffer_len == 0 || hw_config == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    memset(hw_config, 0, sizeof(*hw_config));

    gsc_fwu_img_layout_reset(&layout);

    /*
     * Parse the image, check that the image layout is correct and store it in
     * the library context
     */
    ret = gsc_fwu_img_layout_parse(&layout, buffer, buffer_len, GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    return gsc_image_hw_config(&layout, hw_config);
}

int igsc_hw_config_compatible(IN const struct igsc_hw_config *image_hw_config,
                               IN const struct igsc_hw_config *device_hw_config)
{
    struct gsc_hw_config_1 *image_hw_config_1;
    struct gsc_hw_config_1 *device_hw_config_1;

    if (image_hw_config == NULL || device_hw_config == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    /* In case of HW that doesn't support hw config just return success */
    if (image_hw_config->format_version == 0 && device_hw_config->format_version == 0)
    {
        return IGSC_SUCCESS;
    }

    if (image_hw_config->format_version != GSC_FWU_GET_CONFIG_FORMAT_VERSION ||
        device_hw_config->format_version != GSC_FWU_GET_CONFIG_FORMAT_VERSION)
    {
        return IGSC_ERROR_NOT_SUPPORTED;
    }

    image_hw_config_1 = (struct gsc_hw_config_1 *)image_hw_config->blob;
    device_hw_config_1 = (struct gsc_hw_config_1 *)device_hw_config->blob;

    if (image_hw_config_1->hw_sku == 0 && device_hw_config_1->hw_sku == 0)
    {
        return IGSC_SUCCESS;
    }
    if (image_hw_config_1->hw_sku & device_hw_config_1->hw_sku)
    {
        return IGSC_SUCCESS;
    }

    return IGSC_ERROR_INCOMPATIBLE;
}

int igsc_image_get_type(IN const uint8_t *buffer,
                        IN const uint32_t buffer_len,
                        OUT uint8_t *type)
{
    struct gsc_fwu_img_layout layout;
    struct igsc_oprom_image *oimg = NULL;
    struct igsc_fwdata_image *fwdata_image = NULL;
    int ret;
    uint8_t img_type = IGSC_IMAGE_TYPE_UNKNOWN;
    uint32_t oimg_type;

    if (type == NULL || buffer == NULL || buffer_len == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    gsc_fwu_img_layout_reset(&layout);

    ret = igsc_image_fwdata_init(&fwdata_image, buffer, buffer_len);
    if (ret == IGSC_SUCCESS)
    {
        img_type = IGSC_IMAGE_TYPE_FW_DATA;
        goto exit;
    }

    ret = gsc_fwu_img_layout_parse(&layout, buffer, buffer_len, GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW);
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

    igsc_image_fwdata_release(fwdata_image);

    *type = img_type;

    return ret;
}

static int reconnect_loop(struct igsc_lib_ctx *lib_ctx)
{
    #define MAX_RECONNECT_RETRIES 200
    unsigned int j;
    int ret;

    /* replace error with debug prints because here failure is expected */
    gsc_suppress_errors(lib_ctx);

    for (j = 0; j < MAX_RECONNECT_RETRIES; j++)
    {
        ret = driver_reconnect(lib_ctx);
        if (ret == IGSC_SUCCESS)
        {
            break;
        }
        gsc_debug("reconnect failed #%d\n", j);
        gsc_msleep(300);
    }

    gsc_unsuppress_errors(lib_ctx);

    return ret;
}

static void get_version_loop(struct igsc_lib_ctx *lib_ctx)
{
    /* In order for the underlying library to detect the firmware reset
     * and to update its state for the current handle a dummy command
     * (get fw version) needs to be performed. The expectation is
     * that it will fail eventually.
     */
    #define MAX_GET_VERSION_RETRIES 20
    struct igsc_fw_version version;
    unsigned int i;

    /* replace error with debug prints because here failure is expected */
    gsc_suppress_errors(lib_ctx);

    for (i = 0; i < MAX_GET_VERSION_RETRIES; i++)
    {
        if (gsc_get_fw_version(lib_ctx, &version) != IGSC_SUCCESS)
        {
           break;
        }
        gsc_msleep(100);
    }

    gsc_unsuppress_errors(lib_ctx);

}

#define FWU_TIMEOUT_THRESHOLD_DEFAULT 300000 /* 5 min in units of 1 msec */
#define FWU_TIMEOUT_THRESHOLD_FWDATA  12000 /* 12 sec in units of 1 msec */
#define FWU_TIMEOUT_STEP 500

static int gsc_update(IN struct igsc_device_handle *handle,
                      IN const void *buffer,
                      IN const uint32_t buffer_len,
                      IN igsc_progress_func_t progress_f,
                      IN void *ctx,
                      IN uint32_t payload_type,
                      IN bool force_update)
{
    struct igsc_lib_ctx *lib_ctx;
    int      ret;
    uint32_t bytes_sent = 0;
    uint32_t data_counter = 0;
    uint32_t percentage = 0;
    uint32_t fpt_size = 0;
    const uint8_t *fpt_data = NULL;
    bool retry_update = false;
    bool cp_mode;
    uint32_t sts5 = 0;
    uint32_t timeout_counter = 0;
    uint32_t timeout_threshold;

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

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW || payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA)
    {
        ret = gsc_fwu_img_layout_parse(&lib_ctx->layout, buffer, buffer_len, payload_type);
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

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA)
    {
        fpt_size = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].size;
        fpt_data = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_DATA_IMAGE].content;
    }
    else
    {
        fpt_size = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].size;
        fpt_data = lib_ctx->layout.table[FWU_FPT_ENTRY_FW_IMAGE].content;
    }

    gsc_debug("Update Image Payload size: %d bytes\n", fpt_size);

    gsc_pref_cnt_checkpoint(perf_ctx, "After reading and parsing image");

    ret = gsc_driver_init(lib_ctx, &GUID_METEE_FWU);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }

    ret = get_fwsts(lib_ctx, FWSTS(5), &sts5);
    if (ret != IGSC_SUCCESS)
    {
        goto exit;
    }
    cp_mode = (sts5 & HECI1_CSE_FS_MODE_MASK) == HECI1_CSE_FS_CP_MODE;
    gsc_debug("cp_mode %d, heci sts5 value 0x%x\n", cp_mode, sts5);

    gsc_pref_cnt_checkpoint(perf_ctx, "Before FWU_START");

retry:
    bytes_sent = 0;
    data_counter = 0;
    percentage = 0;

    gsc_pref_cnt_checkpoint(perf_ctx, "Before FWU_START");

    ret = gsc_fwu_start(lib_ctx, payload_type, force_update);
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

        uint32_t chunk_size = gsc_fwu_chunk_size(lib_ctx, fpt_size - bytes_sent);
        ret = gsc_fwu_data(lib_ctx, fpt_data + bytes_sent, chunk_size);
        if (ret != IGSC_SUCCESS)
        {
            if (ret != IGSC_ERROR_PROTOCOL && retry_update == false)
            {
                ret = driver_reconnect(lib_ctx);
                if (ret == IGSC_SUCCESS)
                {
                    retry_update = true;
                    goto retry;
                }
            }
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

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW || payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA)
    {
        get_version_loop(lib_ctx);
    }

    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA)
    {
        timeout_threshold = FWU_TIMEOUT_THRESHOLD_FWDATA;
    }
    else
    {
        timeout_threshold = FWU_TIMEOUT_THRESHOLD_DEFAULT;
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
        gsc_msleep(FWU_TIMEOUT_STEP);
        timeout_counter += FWU_TIMEOUT_STEP;
        if (timeout_counter >= timeout_threshold)
        {
            gsc_error("The firmware failed to finish the update in %u sec timeout\n", timeout_threshold/1000);
            ret = IGSC_ERROR_TIMEOUT;
            goto exit;
        }
    }

    gsc_pref_cnt_checkpoint(perf_ctx, "After PLRs");

    /*
     * After Gfx FW update there is a FW reset so driver reconnect is needed
    */
    if (payload_type == GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW)
    {
        if (cp_mode)
        {
            get_version_loop(lib_ctx);
        }

        ret = reconnect_loop(lib_ctx);
        if (ret == IGSC_SUCCESS)
        {
            /* After the reconnect - send 'no update' message */
            ret = gsc_send_no_update(lib_ctx);
            if (ret != IGSC_SUCCESS)
            {
               gsc_error("failed to send 'no update' message after reset\n");
               goto exit;
            }
        }
        else
        {
            gsc_error("failed to reconnect to the driver after reset\n");
            goto exit;
        }

        /* wait for bit 13 to clear */
        timeout_threshold = FWU_TIMEOUT_THRESHOLD_DEFAULT;
        timeout_counter = 0;
        while (gsc_fwu_is_finishing(lib_ctx))
        {
            if (get_percentage(lib_ctx, &percentage) == IGSC_SUCCESS)
            {
                if (progress_f)
                {
                    progress_f(percentage, 100, ctx);
                }
            }
            gsc_msleep(FWU_TIMEOUT_STEP);
            timeout_counter += FWU_TIMEOUT_STEP;
            if (timeout_counter >= timeout_threshold)
            {
                gsc_error("The firmware failed to report it has finished the update in %u sec timeout\n", timeout_threshold/1000);
                ret = IGSC_ERROR_TIMEOUT;
                goto exit;
            }
        }
        if (cp_mode)
        {
            get_version_loop(lib_ctx);
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

exit:
    gsc_fwu_img_layout_reset(&lib_ctx->layout);

    gsc_driver_deinit(lib_ctx);

    return ret;
}

int igsc_device_fw_update_ex(IN struct igsc_device_handle *handle,
                             IN const uint8_t *buffer,
                             IN const uint32_t buffer_len,
                             IN igsc_progress_func_t progress_f,
                             IN void *ctx,
                             IN struct igsc_fw_update_flags flags)
{
    bool force_update = (flags.force_update == 1);

    return gsc_update(handle, buffer, buffer_len, progress_f, ctx,
                      GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW, force_update);
}

int igsc_device_fw_update(IN struct igsc_device_handle *handle,
                          IN const uint8_t *buffer,
                          IN const uint32_t buffer_len,
                          IN igsc_progress_func_t progress_f,
                          IN void *ctx)
{
    return gsc_update(handle, buffer, buffer_len, progress_f, ctx,
                      GSC_FWU_HECI_PAYLOAD_TYPE_GFX_FW, false);
}

int igsc_iaf_psc_update(IN struct igsc_device_handle *handle,
                        IN const uint8_t *buffer,
                        IN const uint32_t buffer_len,
                        IN igsc_progress_func_t progress_f,
                        IN void *ctx)
{
    return gsc_update(handle, buffer, buffer_len, progress_f, ctx,
                      GSC_FWU_HECI_PAYLOAD_TYPE_IAF_PSC, false);
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
        gsc_error("Bad oprom type %u\n", oprom_type);
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
    uint32_t timeout_counter = 0;

    if (handle == NULL || handle->ctx == NULL || buffer == NULL)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    partition = oprom_type_to_partition(oprom_type);
    if (partition == GSC_FWU_HECI_PART_VERSION_INVALID)
    {
        gsc_error("Bad oprom type %u\n", oprom_type);
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

    ret = gsc_fwu_start(lib_ctx, partition, false);
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
        gsc_msleep(FWU_TIMEOUT_STEP);
        timeout_counter += FWU_TIMEOUT_STEP;
        if (timeout_counter >= FWU_TIMEOUT_THRESHOLD_DEFAULT)
        {
            gsc_error("The firmware failed to finish the update in %u sec timeout\n",
                      FWU_TIMEOUT_THRESHOLD_DEFAULT/1000);
            ret = IGSC_ERROR_TIMEOUT;
            goto exit;
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

    if (!handle || handle->ctx == NULL || !img)
    {
        gsc_error("Invalid parameter: Null pointer\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (oprom_type != IGSC_OPROM_DATA && oprom_type != IGSC_OPROM_CODE)
    {
        gsc_error("Invalid parameter: wrong oprom type %u\n", oprom_type);
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    ret = image_oprom_get_buffer(img, oprom_type, &buffer, &buffer_len);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    if (buffer == NULL || buffer_len == 0 || buffer_len > IGSC_MAX_IMAGE_SIZE)
    {
        gsc_error("Image size (%zu) too big\n", buffer_len);
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
        msg = "Num of bytes to read/write/erase is wrong";
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
    case GSC_FWU_STATUS_LOWER_ARB_SVN:
        msg = "Update to Image with lower ARB SVN is not allowed";
        break;
    case GSC_FWU_STATUS_LOWER_TCB_SVN:
        msg = "Update to Image with lower TCB SVN is not allowed";
        break;
    case GSC_FWU_STATUS_LOWER_VCN:
        msg = "Update to Image with lower VCN is not allowed";
        break;
    case GSC_FWU_STATUS_UPDATE_IUP_SVN:
        msg = "Update Image must not have SVN smaller than SVN of Flash Image";
        break;
    case GSC_FWU_STATUS_UPDATE_IUP_VCN:
        msg = "Update Image must not have VCN smaller than VCN of Flash Image";
        break;
    case GSC_FWU_STATUS_UPDATE_IMAGE_LEN:
        msg = "Update Image length is not the same as Flash Image length";
        break;
    case GSC_FWU_STATUS_UPDATE_PV_BIT:
        msg = "Update from PV bit ON to PV bit OFF is not allowed";
        break;
    case GSC_FWU_STATUS_UPDATE_ENGINEERING_MISMATCH:
        msg = "Update between engineering build vs regular build is not allowed";
        break;
    case GSC_FWU_STATUS_UPDATE_VER_MAN_FAILED_OROM:
        msg = "Loader failed to verify manifest signature of OROM";
        break;
    case GSC_FWU_STATUS_UPDATE_DEVICE_ID_NOT_MATCH:
        msg = "Device ID does not match any device ID entry in the array of supported Device IDs in the manifest extension";
        break;
    case GSC_FWU_STATUS_UPDATE_GET_OPROM_VERSION_FAILED:
        msg = "Failed to get OPROM version";
        break;
    case GSC_FWU_STATUS_UPDATE_OROM_INVALID_STRUCTURE:
        msg = "OPROM is not signed";
        break;
    case GSC_FWU_STATUS_UPDATE_VER_MAN_FAILED_GFX_DATA:
        msg = "Loader failed to verify manifest signature of GFX data";
        break;
    case GSC_FWU_STATUS_UPDATE_GFX_DATA_OEM_MANUF_VER:
        msg = "GFX Data OEM manufacturing data version must be bigger than current version";
        break;
    case GSC_FWU_STATUS_FAILURE:
    /* fall through */
    default:
        msg = "General firmware error";
        break;
    }

    return msg;
}


// In Field Data
static int gsc_fwdata_get_version(struct igsc_lib_ctx *lib_ctx, struct igsc_fwdata_version *version)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;

    struct gsc_fw_data_heci_version_resp *resp;
    struct gsc_fw_data_heci_version_req *req;
    uint8_t command_id = GSC_FWU_HECI_COMMAND_ID_GET_GFX_DATA_UPDATE_INFO;

    if (version == NULL)
    {
        return IGSC_ERROR_INTERNAL;
    }

    req = (struct gsc_fw_data_heci_version_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gsc_fw_data_heci_version_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
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

    version->major_vcn = resp->major_vcn;
    version->major_version = resp->major_version;
    version->oem_manuf_data_version = resp->oem_manuf_data_version_nvm;

    status = IGSC_SUCCESS;

exit:
    return status;
}

static int gsc_fwdata_get_version2(struct igsc_lib_ctx* lib_ctx, struct igsc_fwdata_version2* version)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;

    struct gsc_fw_data_heci_version_resp* resp;
    struct gsc_fw_data_heci_version_req* req;
    uint8_t command_id = GSC_FWU_HECI_COMMAND_ID_GET_GFX_DATA_UPDATE_INFO;

    if (version == NULL)
    {
        return IGSC_ERROR_INTERNAL;
    }

    req = (struct gsc_fw_data_heci_version_req*)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct gsc_fw_data_heci_version_resp*)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
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

    switch (resp->format_version)
    {
    case IGSC_FWDATA_FORMAT_VERSION_1:
        version->data_arb_svn = 0;
        version->data_arb_svn_fitb = 0;
        break;
    case IGSC_FWDATA_FORMAT_VERSION_2:
        version->data_arb_svn = resp->data_arb_svn_nvm;
        version->data_arb_svn_fitb = resp->data_arb_svn_fitb;
        break;
    default:
        gsc_error("Bad version format %u\n", resp->format_version);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    version->flags = resp->flags;
    version->format_version = resp->format_version;
    version->major_vcn = resp->major_vcn;
    version->major_version = resp->major_version;
    version->oem_manuf_data_version = resp->oem_manuf_data_version_nvm;
    version->oem_manuf_data_version_fitb = resp->oem_manuf_data_version_fitb;

    status = IGSC_SUCCESS;

exit:
    return status;
}

static bool fwdata_match_device(struct igsc_device_info *device,
                                struct igsc_fwdata_device_info *fwdata_device)
{
    return (device->vendor_id == fwdata_device->vendor_id) &&
           (device->device_id == fwdata_device->device_id) &&
           (device->subsys_vendor_id == fwdata_device->subsys_vendor_id) &&
           (device->subsys_device_id == fwdata_device->subsys_device_id);
}

//In Field Data API
int igsc_device_fwdata_update(IN  struct igsc_device_handle *handle,
                              IN  const uint8_t *buffer,
                              IN  const uint32_t buffer_len,
                              IN  igsc_progress_func_t progress_f,
                              IN  void *ctx)
{
    if (handle == NULL || handle->ctx == NULL || buffer == NULL || buffer_len == 0)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return gsc_update(handle, buffer, buffer_len, progress_f, ctx,
                      GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA, false);
}

int igsc_device_fwdata_image_update(IN  struct igsc_device_handle *handle,
                                    IN  struct igsc_fwdata_image *img,
                                    IN  igsc_progress_func_t progress_f,
                                    IN  void *ctx)
{
    int ret;
    const uint8_t *buffer = NULL;
    uint32_t buffer_len;

    if (handle == NULL || handle->ctx == NULL || !img)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    ret = image_fwdata_get_buffer(img, &buffer, &buffer_len);
    if (ret != IGSC_SUCCESS)
    {
        return ret;
    }

    if (buffer == NULL || buffer_len == 0 || buffer_len > IGSC_MAX_IMAGE_SIZE)
    {
        gsc_error("Image size (%u) too big\n", buffer_len);
        return IGSC_ERROR_BAD_IMAGE;
    }
    return gsc_update(handle, buffer, buffer_len, progress_f, ctx,
                      GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA, false);
}


int igsc_image_fwdata_init(IN OUT struct igsc_fwdata_image **img,
                           IN const uint8_t *buffer,
                           IN uint32_t buffer_len)
{
    int ret;
    if (img == NULL || buffer == NULL || buffer_len == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    ret = image_fwdata_alloc_handle(img, buffer, buffer_len);
    if (ret != IGSC_SUCCESS)
    {
       return ret;
    }

    gsc_fwu_img_layout_reset(&(*img)->layout);
    ret = gsc_fwu_img_layout_parse(&(*img)->layout, buffer, buffer_len, GSC_FWU_HECI_PAYLOAD_TYPE_FWDATA);
    if (ret != IGSC_SUCCESS)
    {
        igsc_image_fwdata_release(*img);
        *img = NULL;
        return ret;
    }

    ret = image_fwdata_parse(*img);
    if (ret != IGSC_SUCCESS)
    {
        igsc_image_fwdata_release(*img);
        *img = NULL;
    }
    return ret;
}

int igsc_device_fwdata_version(IN  struct igsc_device_handle *handle,
                               OUT struct igsc_fwdata_version *version)
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

    ret = gsc_fwdata_get_version(lib_ctx, version);

    gsc_driver_deinit(lib_ctx);

    return ret;
}

int igsc_device_fwdata_version2(IN  struct igsc_device_handle* handle,
                                OUT struct igsc_fwdata_version2* version)
{
    struct igsc_lib_ctx* lib_ctx;
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

    ret = gsc_fwdata_get_version2(lib_ctx, version);

    gsc_driver_deinit(lib_ctx);

    return ret;
}

int igsc_image_fwdata_version(IN struct igsc_fwdata_image *img,
                              OUT struct igsc_fwdata_version *version)
{
    if (img == NULL || version == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return image_fwdata_get_version(img, version);
}

int igsc_image_fwdata_version2(IN struct igsc_fwdata_image* img,
                               OUT struct igsc_fwdata_version2* version)
{
    if (img == NULL || version == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return image_fwdata_get_version2(img, version);
}

uint8_t igsc_fwdata_version_compare(IN struct igsc_fwdata_version *image_ver,
                                    IN struct igsc_fwdata_version *device_ver)
{
    if (image_ver == NULL || device_ver == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (image_ver->major_version != device_ver->major_version)
    {
        return IGSC_FWDATA_VERSION_REJECT_DIFFERENT_PROJECT;
    }
    if (image_ver->major_vcn > device_ver->major_vcn)
    {
        return IGSC_FWDATA_VERSION_REJECT_VCN;
    }
    if (image_ver->oem_manuf_data_version <= device_ver->oem_manuf_data_version)
    {
        return IGSC_FWDATA_VERSION_REJECT_OEM_MANUF_DATA_VERSION;
    }
    if (image_ver->major_vcn < device_ver->major_vcn)
    {
        return IGSC_FWDATA_VERSION_OLDER_VCN;
    }

    return IGSC_FWDATA_VERSION_ACCEPT;
}

/* Compares input GSC in-field data firmware update version to the flash one and determine ability to update
 *
 * Rules:
 *  The current FW's CSC FW Major version needs to be equal to the update image's CSC FW major version
 *  The current FW's OEM manufacturing data version needs to be smaller or higher than the update image's OEM manufacturing data version
 *  The current FW's data ARB SVN needs to be smaller or equal to the update image's data ARB SVN
 *  The current FW OEM manufacturing date version / data ARB SVN are determined by the fitb valid indication:
 *      In case fitb is not valid (data update context does not exist), the values should be taken from NVM
 *      In case fitb is valid (data update context exist), the values should be taken from fitb.
 */
uint8_t igsc_fwdata_version_compare2(IN struct igsc_fwdata_version2* image_ver,
                                     IN struct igsc_fwdata_version2* device_ver)
{
    uint32_t oem_manuf_data_version_device;
    uint32_t data_arb_svn;

    if (image_ver == NULL || device_ver == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    if (image_ver->format_version < IGSC_FWDATA_FORMAT_VERSION_1 ||
        image_ver->format_version > IGSC_FWDATA_FORMAT_VERSION_2)
    {
        return IGSC_FWDATA_VERSION_REJECT_WRONG_FORMAT;
    }
    if (device_ver->format_version < IGSC_FWDATA_FORMAT_VERSION_1 ||
        device_ver->format_version > IGSC_FWDATA_FORMAT_VERSION_2)
    {
        return IGSC_FWDATA_VERSION_REJECT_WRONG_FORMAT;
    }
    if (image_ver->format_version != device_ver->format_version)
    {
        return IGSC_FWDATA_VERSION_REJECT_WRONG_FORMAT;
    }

    oem_manuf_data_version_device = (device_ver->flags & IGSC_FWDATA_FITB_VALID_MASK) ?
        device_ver->oem_manuf_data_version_fitb : device_ver->oem_manuf_data_version;
    data_arb_svn = (device_ver->flags & IGSC_FWDATA_FITB_VALID_MASK) ?
        device_ver->data_arb_svn_fitb : device_ver->data_arb_svn;

    if (image_ver->major_version != device_ver->major_version)
    {
        return IGSC_FWDATA_VERSION_REJECT_DIFFERENT_PROJECT;
    }
    if (image_ver->major_vcn > device_ver->major_vcn)
    {
        return IGSC_FWDATA_VERSION_REJECT_VCN;
    }

    if (image_ver->format_version == IGSC_FWDATA_FORMAT_VERSION_1)
    {
        if (image_ver->oem_manuf_data_version <= oem_manuf_data_version_device)
        {
            return IGSC_FWDATA_VERSION_REJECT_OEM_MANUF_DATA_VERSION;
        }
    }
    else
    {
        if (image_ver->oem_manuf_data_version == oem_manuf_data_version_device)
        {
            return IGSC_FWDATA_VERSION_REJECT_OEM_MANUF_DATA_VERSION;
        }
    }

    if (image_ver->major_vcn < device_ver->major_vcn)
    {
        return IGSC_FWDATA_VERSION_OLDER_VCN;
    }

    if (image_ver->format_version == IGSC_FWDATA_FORMAT_VERSION_1)
    {
        if (image_ver->data_arb_svn != 0 || data_arb_svn != 0)
        {
            return IGSC_FWDATA_VERSION_REJECT_WRONG_FORMAT;
        }
    }
    else
    {
        if (image_ver->data_arb_svn < data_arb_svn)
        {
            return IGSC_FWDATA_VERSION_REJECT_ARB_SVN;
        }
    }

    return IGSC_FWDATA_VERSION_ACCEPT;
}

int igsc_image_fwdata_count_devices(IN struct igsc_fwdata_image *img,
                                    OUT uint32_t *count)
{
    if (img == NULL || count == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    *count = image_fwdata_count_devices(img);
    return IGSC_SUCCESS;
}

int igsc_image_fwdata_supported_devices(IN struct igsc_fwdata_image *img,
                                        OUT struct igsc_fwdata_device_info *devices,
                                        IN OUT uint32_t *count)
{
    int ret;
    uint32_t pos = 0;

    if (img == NULL || devices == NULL || count == NULL || *count == 0)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    while (((ret = image_fwdata_get_next(img, &devices[pos++])) == IGSC_SUCCESS) && (pos < *count))
    {
        /* empty */
    }

    if (ret == IGSC_ERROR_DEVICE_NOT_FOUND)
    {
        ret = IGSC_SUCCESS;
    }
    *count = pos;

    return ret;
}

int igsc_image_fwdata_match_device(IN struct igsc_fwdata_image *img,
                                   IN struct igsc_device_info *device)
{
    int ret;
    struct igsc_fwdata_device_info fwdata_device;

    if (img == NULL || device == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }
    /* search the device list for a match */
    while ((ret = image_fwdata_get_next(img, &fwdata_device)) == IGSC_SUCCESS)
    {
        if (fwdata_match_device(device, &fwdata_device))
        {
            break;
        }
    }

    return ret;
}

int igsc_image_fwdata_iterator_reset(IN struct igsc_fwdata_image *img)
{
    if (img == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    image_fwdata_iterator_reset(img);

    return IGSC_SUCCESS;

}

int igsc_image_fwdata_iterator_next(IN struct igsc_fwdata_image *img,
                                    OUT struct igsc_fwdata_device_info *device)
{
    if (img == NULL || device == NULL)
    {
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    return image_fwdata_get_next(img, device);
}

int igsc_image_fwdata_release(IN struct igsc_fwdata_image *img)
{
    if (img != NULL)
    {
        gsc_fwu_img_layout_reset(&(img->layout));
    }
    image_fwdata_free_handle(img);

    return IGSC_SUCCESS;
}

static int mchi_heci_validate_response_header(struct igsc_lib_ctx *lib_ctx,
                                              const struct mkhi_msg_hdr *resp_header,
                                              uint32_t command)
{
    int status;

    if (resp_header == NULL)
    {
        status = IGSC_ERROR_INTERNAL;
        goto exit;
    }

    lib_ctx->last_firmware_status = resp_header->result;

    if (resp_header->group_id != MCHI_GROUP_ID_MCA)
    {
        gsc_error("HECI Response group id is %u instead of expected %u\n",
                  resp_header->group_id, MCHI_GROUP_ID_MCA);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->command != command)
    {
        gsc_error("HECI Response header's command is %u instead of expected %u\n",
                  resp_header->command, command);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp_header->is_response == false)
    {
        gsc_error("HECI Response not marked as response\n");
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

int igsc_device_commit_arb_svn(IN struct igsc_device_handle *handle, OUT uint8_t *fw_error)
{
    int status;
    struct igsc_lib_ctx *lib_ctx;
    struct mchi_arbh_svn_commit_req *req;
    struct mchi_arbh_svn_commit_resp *resp;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;

    if (!handle || !handle->ctx)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in commit arb svn, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MCHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("MCHI is not supported on this device, status %d\n", status);
        return status;
    }

    req = (struct mchi_arbh_svn_commit_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct mchi_arbh_svn_commit_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    gsc_debug("validating buffer\n");

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Internal error - failed to validate buffer %d\n", status);
        goto exit;
    }

    memset(req, 0, request_len);
    req->header.group_id = MCHI_GROUP_ID_MCA;
    req->header.command = MCA_ARBH_SVN_COMMIT;
    req->usage_id = CSE_RBE_USAGE;
    req->reserved0 = 0;
    req->reserved1 = 0;

    gsc_debug("sending command\n");

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->header))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    gsc_debug("result = %u\n", resp->header.result);
    if (fw_error)
    {
        *fw_error = resp->header.result;
    }

    status = mchi_heci_validate_response_header(lib_ctx, &resp->header, MCA_ARBH_SVN_COMMIT);
    if (status != IGSC_SUCCESS)
    {
        goto exit;
    }

    if (resp->header.result != 0)
    {
        gsc_error("ARB SVN commit command failed with error %u\n", resp->header.result);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = IGSC_SUCCESS;
    gsc_debug("ARB SVN commit success\n");


exit:
    gsc_driver_deinit(lib_ctx);

    gsc_debug("status = %d\n", status);

    return status;
}

int igsc_device_get_min_allowed_arb_svn(struct igsc_device_handle *handle,
                                        uint8_t *min_allowed_svn)
{
    int status;
    struct igsc_lib_ctx *lib_ctx;
    struct mchi_arbh_svn_get_info_req *req;
    struct mchi_arbh_svn_get_info_resp *resp;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    unsigned int i;
    bool found = false;

    if (!handle || !handle->ctx || !min_allowed_svn)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in get min allowed arb svn, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MCHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("MCHI is not supported on this device, status %d\n", status);
        return status;
    }

    req = (struct mchi_arbh_svn_get_info_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct mchi_arbh_svn_get_info_resp *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    gsc_debug("validating buffer\n");

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Internal error - failed to validate buffer %d\n", status);
        goto exit;
    }

    memset(req, 0, request_len);
    req->header.group_id = MCHI_GROUP_ID_MCA;
    req->header.command = MCA_ARBH_SVN_GET_INFO;

    gsc_debug("sending command\n");

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    if (received_len < sizeof(resp->header))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    gsc_debug("result = %u\n", resp->header.result);

    status = mchi_heci_validate_response_header(lib_ctx, &resp->header, MCA_ARBH_SVN_GET_INFO);
    if (status != IGSC_SUCCESS)
    {
        goto exit;
    }

    if (resp->header.result != 0)
    {
        gsc_error("Get ARB SVN Info command failed with error %u\n", resp->header.result);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (resp->num_entries > (lib_ctx->working_buffer_length - response_len) /
                            sizeof(struct mchi_arbh_svn_info_entry))
    {
        gsc_error("Too many entries in HECI response %u\n", resp->num_entries);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    if (received_len < response_len + resp->num_entries * sizeof(struct mchi_arbh_svn_info_entry))
    {
        gsc_error("Error in HECI read - bad size %zu, num of entries %u, expected size %zu\n",
                  received_len, resp->num_entries,
                  received_len + resp->num_entries * sizeof(struct mchi_arbh_svn_info_entry));
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    for (i = 0; i < resp->num_entries; i++)
    {
        gsc_debug("entry[%u] usage_id %u min_svn %u\n", i, resp->entries[i].usage_id,
                  resp->entries[i].min_allowed_svn);
        if (resp->entries[i].usage_id == CSE_RBE_USAGE)
        {
            *min_allowed_svn = resp->entries[i].min_allowed_svn;
            found = true;
            break;
        }
    }

    if (!found)
    {
        gsc_error("Did not found entry with usage_id %u\n", CSE_RBE_USAGE);
        status = IGSC_ERROR_PROTOCOL;
        goto exit;
    }

    status = IGSC_SUCCESS;
    gsc_debug("Get ARB SVN Info success\n");

exit:
    gsc_driver_deinit(lib_ctx);

    gsc_debug("status = %d\n", status);

    return status;
}

#define MCHI_READ_FILE_DOES_NOT_EXIST 3

static int mchi_read_chunk(IN  struct igsc_lib_ctx *lib_ctx,
                           IN uint32_t file_id, IN uint32_t offset,
                           IN uint32_t length, OUT void *buffer,
                           OUT uint32_t *received_data_len)
{
    int status;
    size_t request_len;
    size_t response_len;
    size_t received_len = 0;
    size_t buf_len;
    struct mchi_read_file_ex_req *req;
    struct mchi_read_file_ex_res *resp;
    uint32_t copy_size;

    req = (struct mchi_read_file_ex_req *)lib_ctx->working_buffer;
    request_len = sizeof(*req);

    resp = (struct mchi_read_file_ex_res *)lib_ctx->working_buffer;
    response_len = sizeof(*resp);
    buf_len = lib_ctx->working_buffer_length;

    gsc_debug("read chunk: file id 0x%x, offset %u, length %u\n", file_id, offset, length);

    gsc_debug("validating buffer\n");

    status = gsc_fwu_buffer_validate(lib_ctx, request_len, response_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Internal error - failed to validate buffer %d\n", status);
        return status;
    }

    memset(req, 0, request_len);
    req->header.group_id = MCHI_GROUP_ID_MCA;
    req->header.command = MCHI_READ_FILE_EX;
    req->file_id = file_id;
    req->offset = offset;
    req->data_size = length;
    req->flags = 0;

    gsc_debug("sending command\n");

    status = gsc_tee_command(lib_ctx, req, request_len, resp, buf_len, &received_len);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        return status;
    }

    if (received_len < sizeof(resp->header))
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        return IGSC_ERROR_PROTOCOL;
    }

    gsc_debug("result = %u\n", resp->header.result);

    status = mchi_heci_validate_response_header(lib_ctx, &resp->header, MCHI_READ_FILE_EX);
    if (status != IGSC_SUCCESS)
    {
        return status;
    }

    if (resp->header.result == MCHI_READ_FILE_DOES_NOT_EXIST)
    {
        /* Special case - the file does not exist. It's legitimate, return success and 0 size */
        *received_data_len = 0;
        gsc_debug("Requested file does not exist\n");
        return IGSC_SUCCESS;
    }

    if (resp->header.result != 0)
    {
        gsc_error("mchi read file command failed with error %u\n", resp->header.result);
        return IGSC_ERROR_PROTOCOL;
    }

    if (received_len < response_len)
    {
        gsc_error("Error in HECI read - bad size %zu\n", received_len);
        return IGSC_ERROR_PROTOCOL;
    }

    if (received_len - response_len < resp->data_size)
    {
        gsc_error("Error in HECI read - bad data size (%u), received %zu bytes\n",
                  resp->data_size, received_len);
        return IGSC_ERROR_PROTOCOL;
    }

    copy_size = resp->data_size;
    if (length < resp->data_size)
    {
       /* this means we received more data than we have asked for, just truncate it */
        copy_size = length;
    }

    if (gsc_memcpy_s(buffer, length, resp->data, copy_size))
    {
        gsc_error("Copy of file data failed, requested %u bytes, received %u bytes, copied %u bytes\n",
                  length, resp->data_size, copy_size);
        return IGSC_ERROR_PROTOCOL;
    }

    gsc_debug("mchi read chunk success, requested %u bytes, received %u bytes, copied %u bytes\n",
              length, resp->data_size, copy_size);

    *received_data_len = copy_size;

    return IGSC_SUCCESS;
}

static int mchi_read_file(IN  struct igsc_device_handle *handle,
                          IN uint32_t file_id, IN uint32_t size,
                          OUT void *buffer, OUT uint32_t *received_data_size)
{
    int status;
    uint32_t cur_size = size;
    uint32_t cur_offset = 0;
    uint32_t chunk_len;
    uint32_t max_chunk_len;
    uint32_t received_size = 0;
    struct igsc_lib_ctx *lib_ctx;

    if (!handle || !handle->ctx || !buffer || size == 0 || !received_data_size)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("in mchi reaf file, initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_MCHI);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("GFSP is not supported on this device, status %d\n", status);
        return status;
    }

    if (lib_ctx->working_buffer_length <= sizeof(struct mchi_read_file_ex_res))
    {
       gsc_error("Max heci message length for this heci client is too small: %zu\n",
                 lib_ctx->working_buffer_length);
       status = IGSC_ERROR_INTERNAL;
       goto exit;
    }

    max_chunk_len = (uint32_t)(lib_ctx->working_buffer_length - sizeof(struct mchi_read_file_ex_res));

    while (cur_size > 0)
    {
        chunk_len = (cur_size > max_chunk_len) ? max_chunk_len : cur_size;

        status = mchi_read_chunk(lib_ctx, file_id, cur_offset,
                                 chunk_len, (uint8_t *)buffer + cur_offset, &received_size);
        if (status != IGSC_SUCCESS)
        {
           gsc_error("Failed to read the chunk at offset %u, status %d\n", cur_offset, status);
           goto exit;
        }

        gsc_debug("Got chunk at offset %u, requested size %u, received size %u\n",
                  cur_offset, chunk_len, received_size);

        if (received_size > chunk_len)
        {
           /* Something is wrong, we received more data than requested */
           status = IGSC_ERROR_INTERNAL;
           cur_offset += chunk_len;
           goto exit;
        }
        else if (received_size < chunk_len)
        {
           /* This means that the actual file size is smaller than the requested one, and that
            * we have finished reading the file
            */
           cur_offset += received_size;
           goto exit;
        }
        else
        {
           cur_offset += received_size;
           cur_size -= received_size;
        }
    }

exit:
    gsc_driver_deinit(lib_ctx);

    *received_data_size = cur_offset;

    gsc_debug("ret = %d, received %u bytes\n", status, cur_offset);

    return status;
}

int igsc_device_oem_version(IN  struct igsc_device_handle *handle,
                            OUT struct igsc_oem_version *version)
{
    int ret;
    uint32_t received_version_size;

    if (!handle || !version)
    {
       gsc_error("Invalid parameters\n");
       return IGSC_ERROR_INVALID_PARAMETER;
    }

    ret = mchi_read_file(handle, FILE_ID_MCA_OEM_VERSION,
                         IGSC_MAX_OEM_VERSION_LENGTH, version->version,
                         &received_version_size);
    if (ret != IGSC_SUCCESS)
    {
       gsc_error("Failed to read OEM_VERSION file, ret=%d\n", ret);
       return ret;
    }

    gsc_debug("ret = %d, received %u bytes\n", ret, received_version_size);

    if (received_version_size == 0 || received_version_size > IGSC_MAX_OEM_VERSION_LENGTH)
    {
       gsc_error("Received wrong size of OEM_VERSION file (%u)\n", received_version_size);
       return IGSC_ERROR_PROTOCOL;
    }

    gsc_trace_hex_dump("OEM Version:", version->version, received_version_size);

    version->length = (uint16_t) received_version_size;
    return ret;
}

int igsc_read_fw_status_reg(IN struct igsc_device_handle *handle,
                            IN uint32_t fwsts_index,
                            OUT uint32_t *fwsts_value)
{
    int status;
    struct igsc_lib_ctx *lib_ctx;

    if (!handle || !handle->ctx || !fwsts_value || fwsts_index > IGSC_MAX_FW_STATUS_INDEX)
    {
        gsc_error("Bad parameters\n");
        return IGSC_ERROR_INVALID_PARAMETER;
    }

    lib_ctx = handle->ctx;

    gsc_debug("read fw status: initializing driver\n");

    status = gsc_driver_init(lib_ctx, &GUID_METEE_FWU);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Cannot initialize HECI client, status %d\n", status);
        return status;
    }

    status = get_fwsts(lib_ctx, fwsts_index, fwsts_value);
    if (status != IGSC_SUCCESS)
    {
        gsc_error("Invalid HECI message response %d\n", status);
        goto exit;
    }

    gsc_debug("fw_sts[%u] = 0x%x\n", fwsts_index, *fwsts_value);

exit:
    gsc_driver_deinit(lib_ctx);

    gsc_debug("ret = %d\n", status);

    return status;
}
