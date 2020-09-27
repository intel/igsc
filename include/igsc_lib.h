/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */

/**
 * @file igsc_lib.h
 * @brief Intel Graphics System Controller Library API
 */

#ifndef __IGSC_LIB_H__
#define __IGSC_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

/** @cond INTERNAL_HIDDEN */
#ifndef IN
#define IN
#endif /* IN */
#ifndef OUT
#define OUT
#endif /* OUT */
/** @endcond */

#include <stdint.h>
#include <stdbool.h>
#include "igsc_export.h"
/**
 * A file descriptor
 * @typedef igsc_handle_t
 * @n
 * Under Linux: file descriptor int fd = open(2)
 * @n
 * Under Windows: HANDLE handle = CreateFile()
 */
#ifdef __linux__
typedef int igsc_handle_t;
#define IGSC_INVALID_DEVICE_HANDLE (-1)
#else /* __linux__ */
typedef void *igsc_handle_t;
#define IGSC_INVALID_DEVICE_HANDLE ((void *)0)
#endif /* __linux__ */

/**
 * Structure to store fw version data
 */
struct igsc_fw_version {
    char       project[4]; /**< Project code name */
    uint16_t   hotfix;     /**< FW Hotfix Number */
    uint16_t   build;      /**< FW Build Number */
};

/**
 * versions comparison results
 */
enum igsc_version_compare_result {
    IGSC_VERSION_ERROR = 0,          /**< An internal error during comparison */
    IGSC_VERSION_NOT_COMPATIBLE = 1, /**< cannot compare, the update image is for a different platform */
    IGSC_VERSION_NEWER = 2,          /**< update image version is newer than the one on the device */
    IGSC_VERSION_EQUAL = 3,          /**< update image version is equal to the one on the device */
    IGSC_VERSION_OLDER = 4,          /**< update image version is older than the one on the device */
};

/**
 * OPROM partition version size in bytes
 */
#define IGSC_OPROM_VER_SIZE 8
/**
 * Structure to store OPROM version data
 */
struct igsc_oprom_version {
    char version[IGSC_OPROM_VER_SIZE]; /**< OPROM Version string */
};

/**
 * OPROM partition type
 */
enum igsc_oprom_type {
    IGSC_OPROM_NONE = 0,     /**< OPROM INVALID PARTITION */
    IGSC_OPROM_DATA = 0x01,  /**< OPROM data (VBT) */
    IGSC_OPROM_CODE = 0x02,  /**< OPROM code (VBIOS and GOP) */
};

/**
 * subsystem vendor and device id support by the OPROM image
 * as defined by PCI.
 */
struct igsc_oprom_device_info {
  uint16_t subsys_vendor_id; /**< subsystem vendor id */
  uint16_t subsys_device_id; /**< subsystem device id */
};

/**
 * @struct igsc_oprom_image
 * opaque struct for oprom image handle
 */
struct igsc_oprom_image;

/**
 * opaque structure representing device lookup context
 */
struct igsc_device_iterator;

/**
 * A device node path (Linux) or device instance path (Windows) Length
 */
#define IGSC_INFO_NAME_SIZE 256

/**
 * Structure to store GSC device info
 */
struct igsc_device_info {
    char name[IGSC_INFO_NAME_SIZE];  /**<  the device node path */

    uint16_t domain;                 /**< pci domain (Linux only) */
    uint8_t  bus;                    /**< pci bus number for GFX device */
    uint8_t  dev;                    /**< device number on pci bus */
    uint8_t  func;                   /**< func the device function of the */

    uint16_t device_id;              /**< gfx device id */
    uint16_t vendor_id;              /**< gfx device vendor id */
    uint16_t subsys_device_id;       /**< gfx device subsystem device id */
    uint16_t subsys_vendor_id;       /**< gfx device subsystem vendor id */
};

/**
 * @name IGSC_ERRORS
 *     The Library return codes
 * @addtogroup IGSC_ERRORS
 * @{
 */
#define IGSC_ERROR_BASE              0x0000U               /**< Error Base */
#define IGSC_SUCCESS                 (IGSC_ERROR_BASE + 0) /**< Success */
#define IGSC_ERROR_INTERNAL          (IGSC_ERROR_BASE + 1) /**< Internal Error */
#define IGSC_ERROR_NOMEM             (IGSC_ERROR_BASE + 2) /**< Memory Allocation Failed */
#define IGSC_ERROR_INVALID_PARAMETER (IGSC_ERROR_BASE + 3) /**< Invalid parameter was provided */
#define IGSC_ERROR_DEVICE_NOT_FOUND  (IGSC_ERROR_BASE + 4) /**< Requested device was not found */
#define IGSC_ERROR_BAD_IMAGE         (IGSC_ERROR_BASE + 5) /**< Provided image has wrong format */
#define IGSC_ERROR_PROTOCOL          (IGSC_ERROR_BASE + 6) /**< Error in the update protocol */
#define IGSC_ERROR_BUFFER_TOO_SMALL  (IGSC_ERROR_BASE + 7) /**< Provided buffer is too small */
#define IGSC_ERROR_INVALID_STATE     (IGSC_ERROR_BASE + 8) /**< Invalid library internal state */
#define IGSC_ERROR_NOT_SUPPORTED     (IGSC_ERROR_BASE + 9) /**< Unsupported request */
/**
 * @}
 */

/**
 * @def IGSC_MAX_IMAGE_SIZE
 * @brief Maximum firmware image size
 */
#define IGSC_MAX_IMAGE_SIZE (8*1024*1024) /* 8M */

struct igsc_lib_ctx;

/**
 * Structure to store GSC FU device data
 */
struct igsc_device_handle
{
    struct igsc_lib_ctx *ctx; /**< Internal library context */
};

/**
 *  @brief Initializes a GSC Firmware Update device.
 *
 *  @param handle A handle to the device. All subsequent calls to the lib's
 *         functions must be with this handle.
 *  @param device_path A path to the device
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_init_by_device(IN OUT struct igsc_device_handle *handle,
                               IN const char *device_path);

/**
 *  @brief Initializes a GSC Firmware Update device.
 *
 *  @param handle A handle to the device. All subsequent calls to the lib's
 *         functions must be with this handle.
 *  @param dev_handle An open device handle
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
int igsc_device_init_by_handle(IN OUT struct igsc_device_handle *handle,
                               IN igsc_handle_t dev_handle);

/**
 *  @brief Initializes a GSC Firmware Update device.
 *
 *  @param handle A handle to the device. All subsequent calls to the lib's
 *         functions must be with this handle.
 *  @param dev_info A device info structure
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_init_by_device_info(IN OUT struct igsc_device_handle *handle,
                                    IN const struct igsc_device_info *dev_info);

/**
 *  @brief Retrieve device information from the system
 *
 *  @param handle An initialized handle to the device.
 *  @param dev_info A device info structure
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_get_device_info(IN  struct igsc_device_handle *handle,
                                OUT struct igsc_device_info *dev_info);

/**
 *  @brief Closes a GSC Firmware Update device.
 *
 *  @param handle A handle to the device.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_close(IN OUT struct igsc_device_handle *handle);

/**
 *  @brief Retrieves the GSC Firmware Version from the device.
 *
 *  @param handle A handle to the device.
 *  @param version The memory to store obtained firmware version.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_fw_version(IN  struct igsc_device_handle *handle,
                           OUT struct igsc_fw_version *version);

/**
 *  @brief Retrieves the Firmware Version from the provided
 *  firmware update image.
 *
 *  @param buffer A pointer to the buffer with the firmware update image.
 *  @param buffer_len Length of the buffer with the firmware update image.
 *  @param version The memory to store the obtained firmware version.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_fw_version(IN  const uint8_t *buffer,
                          IN  uint32_t buffer_len,
                          OUT struct igsc_fw_version *version);

/**
 *  @brief Callback function template for monitor firmware update progress.
 *
 *  @param sent Number of bytes sent to the firmware.
 *  @param total Total number of bytes in firmware update image.
 *  @param ctx Context provided by caller.
 */
typedef void (*igsc_progress_func_t)(uint32_t sent, uint32_t total, void *ctx);

/**
 *  @brief Perform the firmware update from the provided firmware update image.
 *
 *  @param handle A handle to the device.
 *  @param buffer A pointer to the buffer with the firmware update image.
 *  @param buffer_len Length of the buffer with the firmware update image.
 *  @param progress_f Pointer to the callback function for firmware update
 *         progress monitor.
 *  @param ctx Context passed to progress_f function.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT int
igsc_device_fw_update(IN  struct igsc_device_handle *handle,
                      IN  const uint8_t *buffer,
                      IN  const uint32_t buffer_len,
                      IN  igsc_progress_func_t progress_f,
                      IN  void *ctx);

/**
 *  @brief Compares input fw version to the flash one
 *
 *  @param image_ver pointer to the update image OPROM version
 *  @param device_ver pointer to the device OPROM version
 *
 *  @return
 *  * IGSC_VERSION_NOT_COMPATIBLE if update image is for a different platform
 *  * IGSC_VERSION_NEWER          if update image version is newer than the one on the device
 *  * IGSC_VERSION_EQUAL          if update image version is equal to the one on the device
 *  * IGSC_VERSION_OLDER          if update image version is older than the one on the device
 *  * IGSC_VERSION_ERROR          if NULL parameters were provided
 */
IGSC_EXPORT
uint8_t igsc_fw_version_compare(IN struct igsc_fw_version *image_ver,
                                IN struct igsc_fw_version *device_ver);

/**
 *  @brief Retrieves the GSC OPROM version from the device.
 *
 *  @param handle A handle to the device.
 *  @param oprom_type An OPROM type requested @see enum igsc_oprom_type
 *  @param version The memory to store obtained OPROM version.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_oprom_version(IN struct igsc_device_handle *handle,
                              IN uint32_t oprom_type,
                              OUT struct igsc_oprom_version *version);

/**
 *  @brief Perform the OPROM update from the provided image.
 *
 *  @param handle A handle to the device.
 *  @param oprom_type OPROM part to update @see igsc_oprom_type
 *  @param img A pointer to the parsed oprom image structure.
 *  @param progress_f Pointer to the callback function for OPROM update
 *         progress monitor.
 *  @param ctx Context passed to progress_f function.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_oprom_update(IN  struct igsc_device_handle *handle,
                             IN  uint32_t oprom_type,
                             IN  struct igsc_oprom_image *img,
                             IN  igsc_progress_func_t progress_f,
                             IN  void *ctx);
/**
 * @addtogroup oprom
 * @{
 */

/**
 *  @brief initializes OPROM image handle from the supplied OPROM update image.
 *
 *  @param img OPROM image handle allocated by the function.
 *  @param buffer A pointer to the buffer with the OPROM update image.
 *  @param buffer_len Length of the buffer with the OPROM update image.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_oprom_init(IN OUT struct igsc_oprom_image **img,
                          IN const uint8_t *buffer,
                          IN uint32_t buffer_len);

/**
 *  @brief Retrieves the OPROM version from the supplied OPROM update image.
 *
 *  @param img OPROM image handle
 *  @param version The memory to store the obtained OPROM version.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_oprom_version(IN struct igsc_oprom_image *img,
                             IN enum igsc_oprom_type type,
                             OUT struct igsc_oprom_version *version);

/**
 *  @brief Retrieves the OPROM type from the provided OPROM update image.
 *
 *  @param img OPROM image handle
 *  @param oprom_type The variable to store obtained OPROM image type
 *  @see enum igsc_oprom_type
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_oprom_type(IN struct igsc_oprom_image *img,
                          IN  uint32_t *oprom_type);

/**
 *  @brief Retrieves a count of of different devices supported
 *  by the OPROM update image associated with the handle.
 *
 *  @param img OPROM image handle
 *  @param count the number of devices
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_oprom_count_devices(IN struct igsc_oprom_image *img,
                                   OUT uint32_t *count);

/**
 *  @brief Retrieves a list of supported devices
 *  by the OPROM update image associated with the handle.
 *  The caller supplies allocated buffer `devices` of
 *  `count` size. The function returns `count` filled
 *  with actually returned devices.
 *
 *  @param img OPROM image handle
 *  @param devices list of devices supported by the OPROM image
 *  @param count in the number of devices allocated
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_oprom_supported_devices(IN struct igsc_oprom_image *img,
                                       OUT struct igsc_oprom_device_info *devices,
                                       IN OUT uint32_t *count);
/**
 *  @brief check if oprom image can be applied on the device.
 *
 *  @param img OPROM image handle
 *  @param request_type type of oprom device to match
 *  @param device physical device info
 *
 *  @return
 *    * IGSC_SUCCESS if device is on the list of supported devices.
 *    * IGSC_ERROR_DEVICE_NOT_FOUND otherwise.
 */
IGSC_EXPORT
int igsc_image_oprom_match_device(IN struct igsc_oprom_image *img,
                                  IN enum igsc_oprom_type request_type,
                                  IN struct igsc_device_info *device);
/**
 *  @brief reset the iterator over supported devices
 *
 *  @param img OPROM image handle
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_oprom_iterator_reset(IN struct igsc_oprom_image *img);

/**
 *  @brief progress the supported device iterator
 *  and return the oprom device info
 *
 *  @param img OPROM image handle
 *  @param device OPROM device information.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_oprom_iterator_next(IN struct igsc_oprom_image *img,
                                   OUT struct igsc_oprom_device_info *device);

/**
 *  @brief release the OPROM image handle
 *
 *  @param img OPROM image handle
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_image_oprom_release(IN struct igsc_oprom_image *img);

/**
 *  @brief Compares input oprom version to the flash one
 *
 *  @param image_ver pointer to the update image OPROM version
 *  @param device_ver pointer to the device OPROM version
 *
 *  @return
 *  * IGSC_VERSION_NOT_COMPATIBLE if update image is for a different platform
 *  * IGSC_VERSION_NEWER          if update image version is newer than the one on the device
 *  * IGSC_VERSION_EQUAL          if update image version is equal to the one on the device
 *  * IGSC_VERSION_OLDER          if update image version is older than the one on the device
 *  * IGSC_VERSION_ERROR          if NULL parameters were provided
 */
IGSC_EXPORT
uint8_t igsc_oprom_version_compare(const struct igsc_oprom_version *image_ver,
                                   const struct igsc_oprom_version *device_ver);
/**
 * @}
 */

/**
 * @addtogroup enumeration
 * @{
 */

/**
 *  @brief Create iterator for devices capable of FW update.
 *
 *  @param iter pointer to return the iterator pointer
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_iterator_create(struct igsc_device_iterator **iter);

/**
 *  @brief Obtain next devices capable of FW update.
 *
 *  @param iter pointer to iterator.
 *  @param info pointer for device information.
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
int igsc_device_iterator_next(struct igsc_device_iterator *iter,
                              struct igsc_device_info *info);

/**
 *  @brief Free iterator for devices capable of FW update.
 *
 *  @param iter pointer to iterator
 *
 *  @return IGSC_SUCCESS if successful, otherwise error code.
 */
IGSC_EXPORT
void igsc_device_iterator_destroy(struct igsc_device_iterator *iter);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif
#endif /* __IGSC_LIB_H__ */
