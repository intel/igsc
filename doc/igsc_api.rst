2. The Library API
------------------
 .. todo:

1. Error codes

2. Enumeration Interface

3. Samples

4. Library API versioning.

2.1 Introduction
~~~~~~~~~~~~~~~~~

The library support C library interface with most simplicity
in mind. The library supports both Linux and Windows.

The API is divided into 3 groups:

1. **Device FW API**: This API provides wrapper for accessing the GSC Firmware API.
   The API requires device access. This API includes actual image update
   functionality.

2. **Image API**: Provides API for retrieving the required information from
   the update images and utilizes library image parsing capabilities.

3. **Device API**: API utilizing underlying operating system in order
   to enumerate and access graphics device and retrieve information.


Orthogonally the API provides facility to update GSC Firmware and the OPROM
image.

2.2 Types defined by the library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Device path. On a Linux system this type represent a device node path
   on Windows this 'device instance path'.

`Example:`

    * Linux: **/dev/meiX**

    * Windows: **"\\?\DISPLAY#INTC_HECI_2#7&1077c94e&0&UID60434#{5315db55-e7c7-4e67-b396-800a75dd6fe4}"**

.. code-block:: c

    const char *device_path;

2. Device System Handle

  * *Under Linux:* A file descriptor returned by `int open(2)`

  * *Under Windows:* A file handle returned by `HANDLE CreateFile()`

.. code-block:: c

   #ifdef __linux__
   typedef int igsc_handle_t;
   #else /* __linux__ */
   typedef void* igsc_handle_t;
   #endif /* __linux__ */


2. Device Handle: Internal handle used by the library

.. code-block:: c

    struct igsc_device_handle {
        struct igsc_lib_ctx *ctx;         /**< Internal library context */
    };


3 . The device system information retrieved from the operating system.

.. code-block:: c

   struct igsc_device_info {
         char name[256];                  /**< the device node path */

         uint16_t domain;                 /**< pci domain for GFX device */
         uint8_t  bus;                    /**< pci bus number for GFX device */
         uint8_t  dev;                    /**< device number on pci bus */
         uint8_t  func;                   /**< device function number */

         uint16_t device_id;              /**< gfx device id */
         uint16_t vendor_id;              /**< gfx device vendor id */
         uint16_t subsys_device_id;       /**< gfx device subsystem device id */
         uint16_t subsys_vendor_id;       /**< gfx device subsystem vendor id */
   }

4. Version comparison return values

.. code-block:: c

    enum igsc_version_compare_result {
        IGSC_VERSION_ERROR = 0,          /**< An internal error during comparison */
        IGSC_VERSION_NOT_COMPATIBLE = 1, /**< cannot compare, the update image is for a different platform */
        IGSC_VERSION_NEWER = 2,          /**< update image version is newer than the one on the device */
        IGSC_VERSION_EQUAL = 3,          /**< update image version is equal to the one on the device */
        IGSC_VERSION_OLDER = 4,          /**< update image version is older than the one on the device */
    };

5. Hardware configuration data. This is an opaque type as the hardware configuration and format can change between generations

.. code-block:: c

   struct igsc_hw_config {
       uint32_t format_version;
       uint8_t blob[48];
   };

7. Structure to store device subsystem ids

.. code-block:: c

   struct igsc_subsystem_ids {
       uint16_t ssvid;
       uint16_t ssdid;
   };

8. Structure to store oem version data

.. code-block:: c

   #define IGSC_MAX_OEM_VERSION_LENGTH 256

   struct igsc_oem_version {
       uint16_t length; /**< actual OEM version length */
       uint8_t  version[IGSC_MAX_OEM_VERSION_LENGTH];  /**< buffer to store oem version */
   };

9. Structure to store ifr binary version data

.. code-block:: c

    struct igsc_ifr_bin_version {
        uint16_t   major;      /**< IFR Binary Major Number */
        uint16_t   minor;      /**< IFR Binary Minor Number */
        uint16_t   hotfix;     /**< IFR Binary Hotfix Number */
        uint16_t   build;      /**< IFR Binary Build Number */
    };

10. Structure to store psc version data

.. code-block:: c

    struct igsc_psc_version {
        uint32_t   cfg_version; /**< PSC configuration version */
        uint32_t   date;        /**< PSC date */
    };


2.3 Device Access:
~~~~~~~~~~~~~~~~~~

1. Initialization

  * Initialization of the device by the device path

    * Linux: **/dev/meiX**

    * Windows: **PCI\VEN_8086&DEV_9D3A&SUBSYS_225D17AA&REV_21\3&11583659&0&B0**


    .. code-block:: c

        int igsc_device_init_by_device(IN OUT struct igsc_device_handle *handle,
                                       IN const char *device_path);


  * Initialization of the device by a handle

    Linux: An opened file descriptor
    Windows: `TBD`

    .. code-block:: c

        int igsc_device_init_by_handle(IN OUT struct igsc_device_handle *handle,
                                       IN igsc_handle_t handle);

  * Initialization of the device by device info

    Open igsc device by supplied device info obtained from enumeration API.

    .. code-block:: c

        int igsc_device_init_by_device_info(IN OUT struct igsc_device_handle *handle,
                                            IN struct igsc_device_info *dev_info);


2. Closing

.. code-block:: c

    int igsc_device_close(IN OUT struct igsc_device_handle *handle);


3. Retrieve device information

  * Retrieve device information from the PCIe system

  .. code-block:: c

       int igsc_device_get_device_info(IN  struct igsc_device_handle *handle,
                                       OUT struct igsc_info_device *info);

  * Update device information from the firmware

  .. code-block:: c

       int igsc_device_update_device_info(IN  struct igsc_device_handle *handle,
                                          OUT struct igsc_device_info *dev_info);

   * Retrieve the subsystem ids (vid/did) from the device

  .. code-block:: c

       int igsc_device_subsystem_ids(IN struct  igsc_device_handle *handle,
                                     OUT struct igsc_subsystem_ids *ssids);


2.4 Thread safety
~~~~~~~~~~~~~~~~~~~~~~~~

The library supports multithreading but is not thread-safe.
Every thread should either initialize and use its own igsc_device_handle
or a locking mechanism should be implemented by the caller to ensure
that only one thread uses the handle at any time.

2.5 GSC Firmware Update
~~~~~~~~~~~~~~~~~~~~~~~~

1. Firmware Version

The structure represents the device firmware version.

.. code-block:: c

    struct igsc_fw_version {
        char       project[4]; /**< Project code name */
        uint16_t   hotfix;     /**< FW Hotfix Number */
        uint16_t   build;      /**< FW Build Number */
    };


**Version comparison logic is**


.. code-block:: c

    if (Image Project != Device Project)
        Incompatible Image

    if (Image HW Config !~ Device HW Config)
        Incompatible Image

    if ((Image Hotfix version == Device Hotfix version) &&
        (Image Build version <= Device Build version)) ||
       (Image Hotfix version < Device Hotfix version):
        Downgrade()
    else
        Upgrade()


2. Retrieve the firmware version from the device:

.. code-block:: c

    int igsc_device_fw_version(IN  struct igsc_device_handle *handle,
                               OUT struct igsc_fw_version *version);


3. Retrieve the firmware version form the supplied image.

.. code-block:: c

    int igsc_image_fw_version(IN  const uint8_t *buffer,
                              IN  uint32_t buffer_len,
                              OUT struct igsc_fw_version *version);

4. Retrieve the device hardware configuration.

.. code-block:: c

    int igsc_device_hw_config(IN  struct igsc_device_handle *handle,
                              OUT struct igsc_hw_config *hw_config);


5. Retrieve the hardware configuration supported by the supplied firmware


.. code-block:: c

    int igsc_image_hw_config(IN  const uint8_t *buffer,
                             IN  uint32_t buffer_len,
                             OUT struct igsc_hw_config *hw_config);

6. Convert the hardware configuration to a printable string

.. code-block:: c

    int igsc_hw_config_to_string(struct igsc_hw_config *hw_config,
                                 char *buf, size_t length);

7.  Check whether image hardware configuration compatible with device hardware configuration.


.. code-block:: c

   bool igsc_hw_config_compatible(IN const struct igsc_hw_config *image_hw_config,
                               IN const struct igsc_hw_config *device_hw_config);

8. A type of the progress function: A function provided by the caller,
   intended to reflect the progress of the update.

.. code-block:: c

   typedef void (*igsc_progress_func_t)(IN uint32_t sent,
                                        IN uint32_t total,
                                        IN void *ctx);


9. Firmware update of the device: The function get buffer in memory
   and send it to the device. It calls progress function handler
   for each chunk it sends.

.. note::

   The device will undergo reset as a part of firmware update flow.

.. code-block:: c

    int igsc_device_fw_update(IN  struct igsc_device_handle *handle,
                              IN  const uint8_t *buffer,
                              IN  const uint32_t buffer_len,
                              IN  igsc_progress_func_t progress_f,
                              IN  void *ctx);

10. The function implements firmware version comparison logic, it returns
    one of values of `enum igsc_version_compare_result`

.. code-block:: c

   uint8_t igsc_fw_version_compare(IN struct igsc_fw_version *image_ver,
                                   IN struct igsc_fw_version *device_ver);


2.6 OPROM Update API:
~~~~~~~~~~~~~~~~~~~~~

1. OPROM version is a string of 8 bytes.

  .. code-block:: c

    struct igsc_oprom_version {
      char version[8];
    };


    **Version comparison logic is**


  .. code-block:: c

    if ((Image major version != Device major version) &&
        (Device Major version != 0)):
        Incompatible Image

    if ((Image minor version == Device minor version) &&
        (Image build version != Device build version)) ||
       (Image minor version > Device minor version):
        Upgrade()
    else
        Downgrade()


2. OPROM Type

  OPROM type bitmask.

  An OPROM update image might be of type data or code or both.

  .. code-block:: c

    enum igsc_oprom_type {
      IGSC_OPROM_NONE = 0x0,
      IGSC_OPROM_DATA = 0x1,
      IGSC_OPROM_CODE = 0x2,
    };


3. OPROM Device Info

  .. code-block:: c

    struct igsc_device_oprom_info {
      uint16_t subvendor_id;
      uint16_t subdevice_id;
    }

4. OPROM Image info


The structure `igsc_oprom_image` is an opaque structure
which holds paring state of the OPROM image information.

  .. code-block:: c

    struct igsc_oprom_image

5. Retrieve device OPROM version for data and code.


  .. code-block:: c

    int igsc_device_oprom_version(IN  struct igsc_device_handle *handle,
                                  IN  uint32_t igsc_oprom_type,
                                  OUT struct igsc_oprom_version *version);

6. OPROM image Information retrieval:

   a. The function allocates and initializes an opaque
      structure `struct igsc_oprom_image` supplied
      OPROM image.

    .. code-block:: c

      int igsc_image_oprom_init(OUT struct igsc_oprom_image **img
                                IN  const uint8_t *buffer,
                                IN  uint32_t buffer_len);

  b. The function retrieve OPROM version from the OPROM image
     associated with the image handle `img`. The OPROM image type
     has to be specified to fetch the version from the correct
     partition. If the image doesn't support specified partition
     `IGSC_ERROR_NOT_SUPPORTED` is returned.

    .. code-block:: c

      int igsc_image_oprom_version(IN  struct igsc_oprom_image *img,
                                   IN  uint32_t igsc_oprom_type,
                                   OUT struct igsc_oprom_version *version);

  c. The function retrieves the type of the OPROM image associated with `img`.
     The function will place a bitmask into type of all supported OPROM images.

    .. code-block:: c

      int igsc_image_oprom_type(IN struct igsc_oprom_image *img
                                OUT uint32_t *type);

  d. The function provides number of supported devices by the image

    .. code-block:: c

      int igsc_image_oprom_count_devices(IN struct igsc_oprom_image *img
                                         OUT uint32_t *count);

  e. The function retrieves list of supported devices by the image

    .. code-block:: c

      int igsc_image_oprom_supported_devices(IN  struct igsc_oprom_image *img,
                                             OUT igsc_device_oprom_info device[],
                                             IN  uint32_t count);

  f. The function provides an iteration step over supported devices.

    .. code-block:: c

      int igsc_image_oprom_next_device(IN struct igsc_oprom_image *img,
                                       OUT igsc_device_info *device);


  g. The function returns IGSC_SUCCESS if device is on the list of supported
     devices, otherwise it returns IGSC_ERROR_DEVICE_NOT_FOUND

    .. code-block:: c

      int igsc_image_oprom_match_device(IN struct igsc_oprom_image *img,
                                        IN igsc_device_info *device)


  h. The function resets the OPROM device iterator over supported devices

    .. code-block:: c

      int igsc_image_oprom_iterator_reset(IN struct igsc_oprom_image *img);

  i. The function releases image handle `img`

    .. code-block:: c

      int igsc_image_oprom_relese(IN struct igsc_oprom_image *img);


7. Update option ROM partitions:

   The function gets a parsed image sends it to the device.
   It calls progress function handler for each chunk it sends.
   In case requested image type is not present in the image
   the function will return an error.

  .. code-block:: c

    int igsc_device_oprom_update(IN  struct igsc_device_handle *handle,
                                 IN  uint32_t igsc_oprom_type oprom_type,
                                 IN  struct igsc_oprom_image *img,
                                 IN  igsc_progress_func_t progress_f,
                                 IN  void *ctx);

  *Example 1:*

    .. code-block:: c

      int main(int argc, char *argv[])
      {
         struct igsc_oprom_image *img;
         uint32_t *buf;
         uint32_t buf_len;
         struct igsc_device_info device, info;
         struct igsc_device_handle *handle = NULL;
         const char *device_path = NULL;

         device_path = argv[1];

         read_image(argv[2], &buf, buf_len);

         igsc_device_init_by_device(&handle, device_path);
         igsc_image_oprom_init(&img, buf, buf_len);

         while (igsc_image_oprom_next_device(img, &info))
         {
           if (compare(device, info))
           {
             igsc_device_oprom_update(handle, IGSC_OPROM_DATA, buf, buf_len);
             break;
           }
         }

         igsc_image_oprom_relese(img);
         igsc_device_close(handle);
      }


  *Example 2:*

    .. code-block:: c

      int main(int argc, char *argv[])
      {
          struct igsc_oprom_image *img = NULL;
          uint32_t *buf = NULL;
          size_t buf_len = 0;
          struct igsc_device_info device;
          struct igsc_device_handle *handle;

          device_path = argv[1];

          read_image(argv[2], &buf, buf_len);

          igsc_device_init_by_device(&handle, device_path);
          igsc_image_oprom_init(&img, buf, buf_len);

          igsc_device_get_info(handle, &devices, sizeof(device));

          if (igsc_image_oprom_match_device(img, device))
          {
             igsc_device_oprom_update(handle, IGSC_OPROM_CODE, buf, buf_len);
          }

         igsc_image_oprom_relese(img);
      }

8. The function implements OPROM version comparison logic, it returns
   one of values of `enum igsc_version_compare_result`

   .. code-block:: c

     uint8_t igsc_oprom_version_compare(const struct igsc_oprom_version *image_ver,
                                        const struct igsc_oprom_version *device_ver);

2.7 IFR (In-Field Repair) functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  In order to increase the lifetime of the discrete GFX die, there is some redundancy added to it.
  In case of failures, CSC firmware will enable reserved HW instead of malfunctioning HW if possible. 
  The SW triggers the tests that are run by the CSC firmware which decides based on the tests
  results whether to replace malfunctioning HW by the redundant one on the next boot.
  After the test a reset should be performed.

  The following commands for querying and triggering the IFR flow are supported:

  a. Get IFR Status:

    This API returns which IFR tests are supported, how many tiles exist and whether IFR
    repairs were previously applied by the firmware.

    .. code-block:: c

      int igsc_ifr_get_status(IN  struct igsc_device_handle *handle,
                              OUT uint8_t   *result,
                              OUT uint32_t  *supported_tests,
                              OUT uint32_t  *ifr_applied,
                              OUT uint8_t   *tiles_num);


    *Example 1:*

    .. code-block:: c

      int main(int argc, char *argv[])
      {
         struct igsc_device_handle *handle = NULL;
         const char *device_path = NULL;
         uint32_t supported_tests = 0;
         uint32_t ifr_applied = 0
         uint8_t  tiles_num = 0;
         uint8_t  result = 0;
         int ret;

         device_path = argv[1];

         igsc_device_init_by_device(&handle, device_path);

         ret = igsc_ifr_get_status(handle, &result, &supported_tests, &ifr_applied, &tiles_num);
         if (ret || result)
         {
             fprintf(stderr, "Failed to get ifr status, returned %d, result %u\n",
                     ret, result);
             return -1;
          }

          printf("Number of tiles: %u\n", tiles_num);
          printf("Supported tests: scan_test: %u, array test: %u\n",
                 !!(supported_tests & IGSC_IFR_SUPPORTED_TEST_SCAN),
                 !!(supported_tests & IGSC_IFR_SUPPORTED_TEST_ARRAY));
          printf("Applied repairs: DSS EN repair: %u, Array repair: %u\n",
                 !!(ifr_applied & IGSC_IFR_REPAIR_DSS_EN)
                 !!(ifr_applied & IGSC_IFR_REPAIR_ARRAY));

         igsc_device_close(handle);
         return 0;
      }


  b. Run IFR Test:

    Provides API for triggering the IFR flow and returns the status
    of the requested test.
    The command will choose which test to run and on which tile to
    run it on (tile 0 / tile 1 / all tiles).
    A scan test is expected to take a few seconds.
    Host SW will receive a response for the IFR request message only
    after the IFR flow completes.
 
    .. code-block:: c

      int igsc_ifr_run_test(IN struct ifr_device_handle *handle,
                            IN uint8_t                  test_type,
                            IN uint8_t                   tiles,
                            OUT uint8_t                 *result,
                            OUT uint8_t                 *run_status,
                            OUT uint32_t                *error_code);

    *Example 2:*

    .. code-block:: c

      int main(int argc, char *argv[])
      {
          struct igsc_device_handle *handle;
          uint8_t run_status = 0;
          uint32_t error_code = 0;
          uint8_t result = 0;
          struct tile_num = 0;
          uint8_t test_type = 0; /* run scan test */
          int ret;

          device_path = argv[1];

          igsc_device_init_by_device(&handle, device_path);

          tile_num.tile_0 = 1; /* run test on the first tile */

          ret = igsc_ifr_run_test(handle, test_type, tile_num, &result, &run_status, &error_code);
          if (ret || result)
          {
              fprintf(stderr, "Failed to run test, returned %d result %u status %u error_code %u\n",
                      ret, result, run_status, error_code);
              return -1;
          }

          printf("error_code is %u run_status is %u\n", error_code, run_status);

          igsc_device_close(handle);
          return 0;
      }

  c. Get PPR test results status:

    Provides API for retrieving results of the Post Package Repair (PPR) test.
    If a specific row has constant or sporadic failures, PPR can be used to
    replace a malfunctioning memory row with a redundant memory row.
    This row replacement is permanent and irreversible.

    .. code-block:: c

     /**
      * PPR test status bit masks
      */
     enum igsc_ppr_test_status_mask
     {
         IGSC_PPR_STATUS_TEST_EXECUTED_MASK = 0x1,
         IGSC_PPR_STATUS_TEST_SUCCESS_MASK = 0x2,
         IGSC_PPR_STATUS_FOUND_HW_ERROR_MASK = 0x4,
         IGSC_PPR_STATUS_HW_ERROR_REPAIRED_MASK = 0x8,
      };


      /**
       * Device PPR status structure
       */
      struct igsc_device_mbist_ppr_status
      {
          uint32_t mbist_test_status; /**< 0 – Pass, Any set bit represents that MBIST on the matching channel has failed */
          uint32_t num_of_ppr_fuses_used_by_fw; /**< Number of PPR fuses used by the firmware */
          uint32_t num_of_remaining_ppr_fuses; /**< Number of remaining PPR fuses */
      };

      /**
       * PPR status structure
       */
      struct igsc_ppr_status
      {
         uint8_t  boot_time_memory_correction_pending; /**< 0 - No pending boot time memory correction, */
                                                       /**< 1 - Pending boot time memory correction     */
         uint8_t  ppr_mode; /**< 0 – PPR enabled, 1 – PPR disabled, 2 – PPR test mode, */
                            /**< 3 – PPR auto run on next boot */
         uint8_t  test_run_status;
         uint8_t  reserved;
         uint32_t ras_ppr_applied; /**< 0 - ppr not applied, 1 - ppr applied, 2 - ppr exhausted */
         uint32_t mbist_completed; /**< 0 - Not Applied, Any set bit represents mbist completed */
         uint32_t num_devices;     /**< real number of devices in the array (on Xe_HP SDV / PVC <= 8) */
         struct   igsc_device_mbist_ppr_status device_mbist_ppr_status[];
      };

      /* Retrieves number of memory PPR devices */
      int igsc_memory_ppr_devices(IN struct igsc_device_handle *handle,
                                  OUT uint32_t *count);

      /*  Retrieves memory PPR status structure data*/
      int igsc_memory_ppr_status(IN struct  igsc_device_handle *handle,
                                 OUT struct igsc_ppr_status *ppr_status);

    *Example 3:*

    .. code-block:: c

      int main(int argc, char *argv[])
      {
          struct igsc_device_handle *handle;
          int ret;
          char *device_path;
          uint32_t device_num = 0;
          struct igsc_ppr_status *ppr_status;

          device_path = argv[1];

          igsc_device_init_by_device(&handle, device_path);

          /* call the igsc library routine to get number of memory ppr devices */
          ret = igsc_memory_ppr_devices(handle, &device_num);
          if (ret)
          {
             fprintf(stderr,"Failed to retrieve memory ppr devices number, return code %d\n", ret);
             return -1;
          }

          /* allocate ppr_status structure according to the number of ppr devices */
          ppr_status = (struct igsc_ppr_status *) malloc(sizeof(struct igsc_ppr_status) +
                                                   device_num * sizeof(struct igsc_device_mbist_ppr_status));
          if (!ppr_status)
          {
              fprintf(stderr, "Failed to allocate memory\n");
              return -1;
          }

          /* call the igsc library routine to get ppr status */
          ret = igsc_memory_ppr_status(handle, device_num, ppr_status);
          if (ret)
          {
              fprintf(stderr, "Failed to retrieve ppr status, return code %d\n", ret);
          }

          free (ppr_status);
          igsc_device_close(handle);
          return ret;
      }

  d. Get number of memory errors:

    Provides API for retrieving the number of memory errors.

    .. code-block:: c

      /**
       * gfsp number of memory errors per tile
       */
      struct igsc_gfsp_mem_err
      {
          uint32_t corr_err;   /**<  Correctable memory errors on this boot and tile */
          uint32_t uncorr_err; /**<  Uncorrectable memory errors on this boot and tile */
      };

      /**
       * gfsp number of memory errors on the card
       */
      struct igsc_gfsp_mem_err
      {
          uint32_t num_of_tiles; /**< Number of entries in errors array(number of available entries */
                                 /**< when passed to function and number of filled entries when returned) */
          struct igsc_gfsp_tile_mem_err errors[]; /**< array of memory errors structs for each tile */
      };

      int igsc_gfsp_count_tiles(IN  struct igsc_device_handle *handle,
                                OUT uint32_t *max_num_of_tiles);


      int igsc_gfsp_memory_errors_num(IN  struct igsc_device_handle *handle,
                                      OUT struct igsc_gfsp_mem_err *tiles);

  e. IFR run Array & Scan tests

   Runs IFR Array and Scan tests on GSC IFR device

    .. code-block:: c

     /**
       * IFR pending reset values definition
       */
     enum igsc_ifr_pending_reset
     {
         IGSC_IFR_PENDING_RESET_NONE = 0, /**< 0 - No reset needed */
         IGSC_IFR_PENDING_RESET_SHALLOW = 1, /**< 1 - Need to perform a shallow reset */
         IGSC_IFR_PENDING_RESET_DEEP = 2, /**< 2 - Need to perform a deep reset */
     };

     /**
      * IFR array and scan test status bit masks
      */
     enum igsc_ifr_array_scan_test_status_mask
     {
         IGSC_ARRAY_SCAN_STATUS_TEST_EXECUTED_MASK = 0x1, /**< 0 - Test executed, 1 - Test not executed */
         IGSC_ARRAY_SCAN_STATUS_TEST_SUCCESS_MASK = 0x2, /**< 0 - Test finished successfully, 1 - Error occurred during test execution */
         IGSC_ARRAY_SCAN_STATUS_FOUND_HW_ERROR_MASK = 0x4, /**< 0 - HW error not found, 1 - HW error found*/
         IGSC_ARRAY_SCAN_STATUS_HW_ERROR_WILL_BE_REPAIRED_MASK = 0x8, /**< 0 - HW error will be fully repaired or no HW error found, 1 - HW error will not be fully repaired */
     };

     enum igsc_ifr_array_scan_extended_status
     {
        IGSC_IFR_EXT_STS_PASSED = 0, /**< Test passed successfully, no repairs needed */
        IGSC_IFR_EXT_STS_SHALLOW_RST_PENDING = 1, /**< Shallow reset already pending from previous test, aborting test */
        IGSC_IFR_EXT_STS_DEEP_RST_PENDING = 2, /**< Deep reset already pending from previous test, aborting test */
        IGSC_IFR_EXT_STS_NO_REPAIR_NEEDED = 3, /**< Test passed, recoverable error found, no repair needed */
        IGSC_IFR_EXT_STS_REPAIRED_ARRAY = 4, /**< est passed, recoverable error found and repaired using array repairs */
        IGSC_IFR_EXT_STS_REPAIRED_SUBSLICE = 5, /**< Test passed, recoverable error found and repaired using Subslice swaps */
        IGSC_IFR_EXT_STS_REPAIRED_ARRAY_SUBSLICE = 6, /**< Test passed, recoverable error found and repaired using array repairs and Subslice swaps*/
        IGSC_IFR_EXT_STS_REPAIR_NOT_SUPPORTED = 7, /**< Test completed, unrecoverable error found, part doesn't support in field repair */
        IGSC_IFR_EXT_STS_NO_RESORCES = 8, /**< Test completed, unrecoverable error found, not enough repair resources available */
        IGSC_IFR_EXT_STS_NON_SUBSLICE = 9, /**< Test completed, unrecoverable error found, non-Subslice failure */
        IGSC_IFR_EXT_STS_TEST_ERROR = 10, /**< Test error */
     };

     int igsc_ifr_run_array_scan_test(IN struct igsc_device_handle *handle,
                                      OUT uint32_t *status,
                                      OUT uint32_t *extended_status,
                                      OUT uint32_t *pending_reset,
                                      OUT uint32_t *error_code);

  f. IFR run memory PPR test

   Runs IFR memory Post Package Repair (PPR) test on GSC IFR device

    .. code-block:: c

     int igsc_ifr_run_mem_ppr_test(IN struct igsc_device_handle *handle,
                                   OUT uint32_t *status,
                                   OUT uint32_t *pending_reset,
                                   OUT uint32_t *error_code);

  g. Get IFR status extended command

   Retrieves the status of GSC IFR device

    .. code-block:: c

     /**
      * IFR supported tests masks
      */
     enum igsc_ifr_supported_tests_masks
     {
        IGSC_IFR_SUPPORTED_TESTS_ARRAY_AND_SCAN = 0x1, /**< 1 - Array and Scan test */
        IGSC_IFR_SUPPORTED_TESTS_MEMORY_PPR = 0x2, /**< 2 - Memory PPR */
     };

     /**
      * IFR hw capabilities masks
      */
     enum igsc_ifr_hw_capabilities_masks
     {
         IGSC_IRF_HW_CAPABILITY_IN_FIELD_REPAIR = 0x1, /**< 1: both in field tests and in field repairs are supported. */
                                                       /**< 0: only in field tests are supported */
         IGSC_IRF_HW_CAPABILITY_FULL_EU_MODE_SWITCH = 0x2, /**< 1: Full EU mode switch is supported */
     };

     /**
      * IFR previous errors masks
      */
     enum igsc_ifr_previous_errors_masks
     {
        IGSC_IFR_PREV_ERROR_DSS_ERR_ARR_STS_PKT = 0x1, /**< DSS Engine error in an array test status packet */
        IGSC_IFR_PREV_ERROR_NON_DSS_ERR_ARR_STS_PKT = 0x2, /**< Non DSS Engine error in an array test status packet */
        IGSC_IFR_PREV_ERROR_DSS_REPAIRABLE_PKT = 0x4, /**< DSS Repairable repair packet in an array test */
        IGSC_IFR_PREV_ERROR_DSS_UNREPAIRABLE_PKT = 0x8, /**< DSS Unrepairable repair packet in an array test */
        IGSC_IFR_PREV_ERROR_NON_DSS_REPAIRABLE_PKT = 0x10, /**< Non DSS Repairable repair packet in an array test */
        IGSC_IFR_PREV_ERROR_NON_DSS_UNREPAIRABLE_PKT = 0x20, /**< Non DSS Unrepairable repair packet in an array test */
        IGSC_IFR_PREV_ERROR_DSS_ERR_SCAN_STS_PKT = 0x40, /**< DSS failure in a scan test packet */
        IGSC_IFR_PREV_ERROR_NON_DSS_ERR_SCAN_STS_PKT = 0x80, /**< Non DSS failure in a scan test packet */
        IGSC_IFR_PREV_ERROR_UNEXPECTED = 0x8000, /**< Unexpected test failure */
     };

     /**
      * IFR repairs masks
      */
     enum igsc_ifr_repairs_mask
     {
        IGSC_IFR_REPAIRS_MASK_DSS_EN_REPAIR = 0x1, /**< DSS enable repair applied */
        IGSC_IFR_REPAIRS_MASK_ARRAY_REPAIR = 0x2, /**< Array repair applied */
     };

     int igsc_ifr_get_status_ext(IN  struct igsc_device_handle *handle,
                                 OUT uint32_t *supported_tests,
                                 OUT uint32_t *hw_capabilities,
                                 OUT uint32_t *ifr_applied,
                                 OUT uint32_t *prev_errors,
                                 OUT uint32_t *pending_reset);

  f. Count tiles on the device

   Retrieves the number of tiles on CSC IFR device.

    .. code-block:: c

      int igsc_ifr_count_tiles(IN  struct igsc_device_handle *handle,
                               OUT uint16_t *supported_tiles); /* Number of supported tiles */

  g. Get IFR tile repair info command

   Retrieves the tile repair info of a specific tile of CSC IFR device.
   The CSC firmware exposes the details about the repairs it performed so far.
   The information is supplied per tile, so if a user wants to get info about each of the 2 tiles
   this API should be called twice with the relevant tile number.

    .. code-block:: c

      int igsc_ifr_get_repair_info(IN  struct igsc_device_handle *handle,
                                   IN uint16_t tile_idx, /* Index of the tile the info is requested from */
                                   OUT uint16_t *used_array_repair_entries, /* Number of array repair entries used by firmware */
                                   OUT uint16_t *available_array_repair_entries, /* Number of available array repair entries */
                                   OUT uint16_t *failed_dss); /* Number of failed DSS */

  h. Get and set ECC configuration:

    Provides API for ECC runtime configuration.

    .. code-block:: c

      int igsc_ecc_config_set(IN  struct igsc_device_handle *handle,
                              IN  uint8_t req_ecc_state,   /* Requested ECC State */
                              OUT uint8_t *cur_ecc_state,  /* Current ECC State after command execution */
                              OUT uint8_t *pen_ecc_state); /* Pending ECC State after command execution */

      int igsc_ecc_config_get(IN  struct igsc_device_handle *handle,
                              OUT uint8_t *cur_ecc_state,   /* Current ECC State */
                              OUT uint8_t *pen_ecc_state);  /* Pending ECC State */

  i. Get memory health indicator

    Provides API for retrieving memory health indicator.

    .. code-block:: c

      enum igsc_gfsp_health_indicators {
          IGSC_HEALTH_INDICATOR_HEALTHY  = 0,
          IGSC_HEALTH_INDICATOR_DEGRADED = 1,
          IGSC_HEALTH_INDICATOR_CRITICAL = 2,
          IGSC_HEALTH_INDICATOR_REPLACE  = 3
      };

      int igsc_gfsp_get_health_indicator(IN struct igsc_device_handle *handle,
                                         OUT uint8_t *health_indicator);

  j. Send generic GFSP command and receive response

    Provides API for sending a generic GFSP command cmd with
    data taken from the in_buffer of size in_buffer_size.
    The data received in the GFSP reply is stored in the
    out_buffer of size out_buffer_size. The actual received data
    size is stored in *actual_response_size.

    .. code-block:: c

      int igsc_gfsp_heci_cmd(struct igsc_device_handle *handle, uint32_t gfsp_cmd,
                             uint8_t* in_buffer, size_t in_buffer_size,
                             uint8_t* out_buffer, size_t out_buffer_size,
                             size_t *actual_response_size);

   k. Send Late Binding payload command

    .. code-block:: c

     /**
       * Late Binding flags
       *
       */
      enum csc_late_binding_flags {
          CSC_LATE_BINDING_FLAGS_IS_PERSISTENT_MASK = 0x1,
      };

      /**
       * Late Binding payload type
       */
      enum csc_late_binding_type {
          CSC_LATE_BINDING_TYPE_INVALID = 0,
          CSC_LATE_BINDING_TYPE_FAN_TABLE,
          CSC_LATE_BINDING_TYPE_VR_CONFIG
      };

      /**
       * Late Binding payload status
       */
      enum csc_late_binding_status {
          CSC_LATE_BINDING_STATUS_SUCCESS           = 0,
          CSC_LATE_BINDING_STATUS_4ID_MISMATCH      = 1,
          CSC_LATE_BINDING_STATUS_ARB_FAILURE       = 2,
          CSC_LATE_BINDING_STATUS_GENERAL_ERROR     = 3,
          CSC_LATE_BINDING_STATUS_INVALID_PARAMS    = 4,
          CSC_LATE_BINDING_STATUS_INVALID_SIGNATURE = 5,
          CSC_LATE_BINDING_STATUS_INVALID_PAYLOAD   = 6,
          CSC_LATE_BINDING_STATUS_TIMEOUT           = 7,
      };

      Provides API for sending a Late Binding HECI command, with
      Late Binding payload type,
      Late Binding flags to be sent to the firmware and
      Late Binding data to be sent to the firmware with the size of the payload data
      as IN parameters and with Late Binding payload status as OUT parameter
      Returns IGSC_SUCCESS if successful, otherwise error code.

      int igsc_device_update_late_binding_config(IN struct  igsc_device_handle *handle,
                                                 IN uint32_t type, /* enum csc_late_binding_type */
                                                 IN uint32_t flags, /* enum csc_late_binding_flags */
                                                 IN uint8_t *payload, IN size_t payload_size,
                                                 OUT uint32_t *status); /* enum csc_late_binding_status */

   l. Send ARB SVN commit command

      Provides API for sending an ARB SVN commit command to the firmware.
      Second parameter return firmware error in case of failure

    .. code-block:: c

      int igsc_device_commit_arb_svn(IN struct  igsc_device_handle *handle, uint8_t *fw_error);

   m. Retrieve minimal allowed ARB SVN

    .. code-block:: c

      int igsc_device_get_min_allowed_arb_svn(IN struct  igsc_device_handle *handle,
                                              OUT uint8_t *min_allowed_svn);


2.8 Device Enumeration API
~~~~~~~~~~~~~~~~~~~~~~~~~~

The device enumeration API provides access to GSC devices installed on the
system, utilizing underlying system level enumeration API. It is less
exhausting than a usual device enumeration API, the API provides the minimal
required interface focused on GSC.

The other objective is to provide a cross platform API for Linux and Windows.

It is still possible to user native enumeration APIs

On Linux it may utilize udev or directly sysfs pci access on Windows can be
done via SetupDi interface.


1. Device iterator is a opaque structure representing device lookup context

.. code-block:: c

   struct igsc_device_iterator;

2. Create iterator structure

.. code-block:: c

    int igsc_device_iterator_create(struct igsc_device_iterator **iter)

3. Destroy iterator structure

.. code-block:: c

    void igsc_device_iterator_destroy(struct igsc_device_iterator *iter);

4. Provide next device on the list. The function allocates new entry in info
   unless the enumeration was exhausted.

.. code-block:: c

    int igsc_device_iterator_next(struct igsc_device_iterator *iter,
                                  struct igsc_device_info *info);

2.9 Retrieving firmware status
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Retrieve the firmware status code of the last operation.


.. code-block:: c

   uint32_t igsc_get_last_firmware_status(IN struct igsc_device_handle *handle);


2. Return the firmware status message corresponding to the firmware status code.

.. code-block:: c

   const char *igsc_translate_firmware_status(IN uint32_t firmware_status);

2.10 Signed in-field firmware data update API

Support SKU specific signed in-field data update.  It allows OEMs to perform
secure in-field update of the configuration data.

1. Firmware Data Version

The structure represents the device firmware data version.
Version 2 adds ARB SVN and other fields.

  .. code-block:: c

     struct igsc_fwdata_version {
        uint32_t oem_manuf_data_version; /**< GSC in-field data firmware OEM manufacturing data version */
        uint16_t major_version;          /**< GSC in-field data firmware major version */
        uint16_t major_vcn;              /**< GSC in-field data firmware major VCN */
     };

    struct igsc_fwdata_version2 {
        uint32_t format_version;         /**< GSC in-field data firmware version format */
        uint32_t oem_manuf_data_version; /**< GSC in-field data firmware OEM manufacturing data version */
        uint32_t oem_manuf_data_version_fitb; /**< GSC in-field data firmware OEM manufacturing data version from FITB */
        uint16_t major_version;          /**< GSC in-field data firmware major version */
        uint16_t major_vcn;              /**< GSC in-field data firmware major VCN */
        uint32_t flags;                  /**< GSC in-field data firmware flags */
        uint32_t data_arb_svn;           /**< GSC in-field data firmware SVN */
        uint32_t data_arb_svn_fitb;      /**< GSC in-field data firmware SVN from FITB */
    };

**Version comparison logic is**

  .. code-block:: c

     if ((Image major version != Device major version) &&
         Incompatible Image

     if (Image major vcn > Device major vcn)
         Incompatible Image

     if (Image oem manufacturing data version <= Device manufacturing data version)
         Incompatible Image

     if (Image major vcn < Device major vcn)
         Downgrade()
     else
         Upgrade()


2. Firmware Data Device Info

  .. code-block:: c

     struct igsc_fwdata_device_info {
        uint16_t vendor_id; /**< vendor id */
        uint16_t device_id; /**< device id */
        uint16_t subsys_vendor_id; /**< subsystem vendor id */
        uint16_t subsys_device_id; /**< subsystem device id */
     }

3. Firmware Data Image info

  The structure `igsc_fwdata_image` is an opaque structure
  which holds parsing state of the firmware data image information.

  .. code-block:: c

     struct igsc_fwdata_image;

4. Firmware data version comparison return values

  .. code-block:: c

     enum igsc_fwdata_version_compare_result {
         IGSC_FWDATA_VERSION_REJECT_VCN = 0,                    /**< VCN version is bigger than device VCN */
         IGSC_FWDATA_VERSION_REJECT_OEM_MANUF_DATA_VERSION = 1, /**< OEM manufacturing data version is not bigger than device OEM version or equal in ver2 comparison */
         IGSC_FWDATA_VERSION_REJECT_DIFFERENT_PROJECT = 2,      /**< major version is different from device major version */
         IGSC_FWDATA_VERSION_ACCEPT = 3,                        /**< update image VCN version is equal than the one on the device, and OEM is bigger */
         IGSC_FWDATA_VERSION_OLDER_VCN = 4,                     /**< update image VCN version is smaller than the one on the device */
         IGSC_FWDATA_VERSION_REJECT_WRONG_FORMAT = 5,           /**< the version format is the wrong one or incompatible */
         IGSC_FWDATA_VERSION_REJECT_ARB_SVN = 6,                /**< update image SVN version is smaller than the one on the device */
     };

5. Retrieve device firmware data version


  .. code-block:: c

     int igsc_device_fwdata_version(IN  struct igsc_device_handle *handle,
                                    OUT struct igsc_fwdata_version *version);
     int igsc_device_fwdata_version2(IN  struct igsc_device_handle *handle,
                                     OUT struct igsc_fwdata_version2 *version);

6. Firmware data image information retrieval:

   a. The function allocates and initializes an opaque
      structure `struct igsc_fwdata_image` for the supplied
      firmware data image.

    .. code-block:: c

       int igsc_image_fwdata_init(IN OUT struct igsc_fwdata_image **img,
                                  IN const uint8_t *buffer,
                                  IN uint32_t buffer_len);

  b. The functions retrieve firmware data version from the firmware data image
     associated with the image handle `img`.

    .. code-block:: c

       int igsc_image_fwdata_version(IN struct igsc_fwdata_image *img,
                                     OUT struct igsc_fwdata_version *version);

       int igsc_image_fwdata_version2(IN struct igsc_fwdata_image *img,
                                      OUT struct igsc_fwdata_version2 *version);

  c. The function provides number of supported devices by the image

    .. code-block:: c

       int igsc_image_fwdata_count_devices(IN struct igsc_fwdata_image *img,
                                           OUT uint32_t *count);

  d. The function retrieves list of supported devices by the image

    .. code-block:: c

       int igsc_image_fwdata_supported_devices(IN struct igsc_fwdata_image *img,
                                               OUT struct igsc_fwdata_device_info *devices,
                                               IN OUT uint32_t *count);

  e. The function resets the oprom device iterator over supported devices

    .. code-block:: c

       int igsc_image_fwdata_iterator_reset(IN struct igsc_fwdata_image *img);

  f. The function provides an iteration step over supported devices.

    .. code-block:: c

       int igsc_image_fwdata_iterator_next(IN struct igsc_fwdata_image *img,
                                           OUT struct igsc_fwdata_device_info *device);

  g. The function returns IGSC_SUCCESS if device is on the list of supported
     devices, otherwise it returns IGSC_ERROR_DEVICE_NOT_FOUND

    .. code-block:: c

       int igsc_image_fwdata_match_device(IN struct igsc_fwdata_image *img,
                                          IN struct igsc_device_info *device);

  i. The function releases image handle `img`

    .. code-block:: c

       int igsc_image_fwdata_release(IN struct igsc_fwdata_image *img);

7. The function implements oprom version comparison logic, it returns
   one of values of `igsc_fwdata_version_compare_result`

   .. code-block:: c

      uint8_t igsc_fw_version_compare(IN struct igsc_fw_version *image_ver,
                                      IN struct igsc_fw_version *device_ver);
8. Update firmware data using parsed image:

   The function gets a parsed firmware data image and sends it to the device.
   It calls progress function handler for each chunk it sends.

  .. code-block:: c

     int igsc_device_fwdata_image_update(IN  struct igsc_device_handle *handle,
                                         IN  struct igsc_fwdata_image *img,
                                         IN  igsc_progress_func_t progress_f,
                                         IN  void *ctx);

9. Update firmware data from a buffer:

   The function gets a buffer that contains a firmware data image, parses it
   and sends it to the device.
   It calls progress function handler for each chunk it sends.

  .. code-block:: c

     int igsc_device_fwdata_update(IN  struct igsc_device_handle *handle,
                                   IN  const uint8_t *buffer,
                                   IN  const uint32_t buffer_len,
                                   IN  igsc_progress_func_t progress_f,
                                   IN  void *ctx);

2.11 IAF Update API
~~~~~~~~~~~~~~~~~~~
Intel Accelerator Fabric Platform Specific Configuration (PSC) update is
done as a blob, without parsing the image and with zero metadata.

1. Update PSC partition:

   The function performs Intel Accelerator Fabric Platform Specific
   Configuration (PSC) update from the provided update data image.

   .. code-block:: c

      int igsc_iaf_psc_update(IN struct igsc_device_handle *handle,
                              IN const uint8_t *buffer,
                              IN const uint32_t buffer_len,
                              IN igsc_progress_func_t progress_f,
                              IN void *ctx);


2.12 Retrieving versions of different firmware components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
All firmware partitions (including IFR and PSC partitions) are identified by version,
as these versions can be changed by a customer or internal teams.
The following APIs retrieve versions of the relevant firmware components.

1. PSC partition version:

   PSC binary contains the Connectivity Die configuration data and exists in the SPI.
   The PSC version is a combination of the fields cfg_version and date of the PSC header
   which resides at the start of the PSC binary.
   In case PSC is absent or not implemented by the firmware, the api returns
   MKHI_STATUS_NOT_FOUND(0x81) or MKHI_STATUS_INVALID_PARAMS(0x85) depending on the
   firmware.

   .. code-block:: c

      int igsc_device_psc_version(IN  struct igsc_device_handle *handle,
                                  OUT struct igsc_psc_version *version);


2. IFR Binary partition version:

   IFR binary contains the In Field Repair test content
   The IFR binary is not a mandatory ingredient in the firmware image.
   In case IFR binary is absent or not implemented by the firmware, the api returns
   MKHI_STATUS_NOT_FOUND(0x81) or MKHI_STATUS_INVALID_PARAMS(0x85) depending on the
   firmware.

   .. code-block:: c

      int igsc_device_ifr_bin_version(IN  struct igsc_device_handle *handle,
                                      OUT struct igsc_ifr_bin_version *version);


3. OEM version:

   The OEM version is Firmware Named Variable which a customer can use to set
   its own version during building the image or at manufacturing line.
   In case OEM version is not implemented by the firmware, the api returns
   MKHI_STATUS_NOT_FOUND(0x81) or MKHI_STATUS_INVALID_PARAMS(0x85) depending on the
   firmware.

   .. code-block:: c

      int igsc_device_oem_version(IN  struct igsc_device_handle *handle,
                                  OUT struct igsc_oem_version *version);
