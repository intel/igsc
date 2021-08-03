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

  * *Under Windows:* A file handle returned by `HANLDE CreateFile()`

.. code-block:: c

   #ifdef __linux__
   typedef int igsc_handle_t;
   #else /* __linux__ */
   typedef void* igsc_handle_t;
   #endif /* __linux__ */


3. Device Handle: Internal handle used by the library

.. code-block:: c

    struct igsc_device_handle {
        struct igsc_lib_ctx *ctx;         /**< Internal library context */
    };


4 . The device system information retrieved from the operating system.

.. code-block:: c

   struct igsc_device_info {
         char name[256];                  /**< the device node path */

         uint16_t domain;                 /**< pci domain (Linux only) */
         uint8_t  bus;                    /**< pci bus number for GFX device */
         uint8_t  dev;                    /**< device number on pci bus */
         uint8_t  func;                   /**< func the device function of the */

         uint16_t device_id;              /**< gfx device id */
         uint16_t vendor_id;              /**< gfx device vendor id */
         uint16_t subsys_device_id;       /**< gfx device subsystem device id */
         uint16_t subsys_vendor_id;       /**< gfx device subsystem vendor id */
   }

5. Version comparison return values

.. code-block:: c

    enum igsc_version_compare_result {
        IGSC_VERSION_ERROR = 0,          /**< An internal error during comparison */
        IGSC_VERSION_NOT_COMPATIBLE = 1, /**< cannot compare, the update image is for a different platform */
        IGSC_VERSION_NEWER = 2,          /**< update image version is newer than the one on the device */
        IGSC_VERSION_EQUAL = 3,          /**< update image version is equal to the one on the device */
        IGSC_VERSION_OLDER = 4,          /**< update image version is older than the one on the device */
    };

6. Hardware configuration data. This is an opaque type as the hardware configuration and format can change between generations

.. code-block:: c

   struct igsc_hw_config {
       uint32_t format_version;
       uint8_t blob[48];
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


3. Retrieve device information from the system

.. code-block:: c

    int igsc_device_get_device_info(IN  struct igsc_device_handle *handle,
                                    OUT struct igsc_info_device *info);

2.4 GSC Firmware Update
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


2.5 OPROM Update API:
~~~~~~~~~~~~~~~~~~~~~

1. OPROM version is a string of 8 bytes.

  .. code-block:: c

    struct igsc_oprom_version {
      char version[8];
    };

  .. note::

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

    struct igsc_oprom_image;

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

  h. The function resets the oprom device iterator over supported devices

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
          struct igsc_device_handle *hadnle;

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

8. The function implements oprom version comparison logic, it returns
   one of values of `enum igsc_version_compare_result`

   .. code-block:: c

   uint8_t igsc_oprom_version_compare(const struct igsc_oprom_version *image_ver,
                                      const struct igsc_oprom_version *device_ver);

2.6 IFR (In-Field Repair) functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  In order to increase the lifetime of the discrete GFX die, there is some redundancy added to it.
  In case of failures, CSC firmware will enable reserved HW instead of malfunctioning HW if possible. 
  The SW triggers the tests that are run by the CSC firmware which decides based on the tests
  results whether to replace malfunctioning HW by the redundant one on the next boot.
  After the test a reset should be performed.

  The following commands for querying and triggering the IFR flow are supported:

1. Get IFR Status:

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


2. Run IFR Test:

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
          struct igsc_device_handle *hadnle;
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

2.7 Device Enumeration API
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

2.8 Retrieving firmware status
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Retrieve the firmware status code of the last operation.


.. code-block:: c

   uint32_t igsc_get_last_firmware_status(IN struct igsc_device_handle *handle);


2. Return the firmware status message corresponding to the firmware status code.

.. code-block:: c

   const char *igsc_translate_firmware_status(IN uint32_t firmware_status);
