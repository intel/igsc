/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020-2022 Intel Corporation
 */
#ifndef __IGSC_INTERNAL_H__
#define __IGSC_INTERNAL_H__

#include <stdint.h>

struct igsc_lib_ctx {
    char *device_path;                /**< GSC device path */
    igsc_handle_t dev_handle;         /**< GSC device handle */
    TEEHANDLE driver_handle;          /**< Context for the driver */
    uint8_t *working_buffer;          /**< Buffer for tee calls */
    size_t working_buffer_length;     /**< Tee buffer length */
    bool driver_init_called;          /**< Driver was initialized */
    struct gsc_fwu_img_layout layout; /**< Context for the image layout */
    uint32_t last_firmware_status;    /**< last status code returned from the firmware */
    bool restore_power_control;       /**< need to restore power control for the device */
    bool suppress_errors;             /**< temporary suppress specific error messages */
    uint32_t tee_prev_log_level;      /**< saved previous log level of metee, to restore */
};

int gsc_fwu_buffer_validate(struct igsc_lib_ctx *lib_ctx,
                            size_t req_sz, size_t resp_sz);

int gsc_tee_command(struct igsc_lib_ctx *lib_ctx,
                    void *req_buf, size_t request_len,
                    void *resp_buf, size_t buf_size,
                    size_t *response_len);

void gsc_driver_deinit(struct igsc_lib_ctx *lib_ctx);
int gsc_driver_init(struct igsc_lib_ctx *lib_ctx, IN const GUID *guid);

#endif /* !__IGSC_INTERNAL_H__ */
