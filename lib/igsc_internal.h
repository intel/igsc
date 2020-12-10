/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020 Intel Corporation
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
};

#endif /* !__IGSC_INTERNAL_H__ */
