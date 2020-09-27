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

3. **Image API**: Provides API for retrieving the required information from
   the update images and utilizes library image parsing capabilities.

1. **Device API**: API utilizing underlying operating system in order
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


2. Device Handle: Internal handle used by the library

.. code-block:: c

    struct igsc_device_handle {
        struct igsc_lib_ctx *ctx;         /**< Internal library context */
    };


3 . The device system information retrieved from the operating system.

.. code-block:: c

   struct igsc_device_info {
         const igsc_path_t  *device_path;
         uint16_t   domain;                /**< linux only */
         uint8_t    bus;
         uint8_t    dev;
         uint8_t    func;

         uint16_t   vendor_id;
         uint16_t   device_id;
         uint16_t   subvendor_id;
         uint16_t   subdevice_id;

         uint8_t    data[TBD];
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
        char       Project[4];
        uint16_t   Hotfix;
        uint16_t   Build;
    };


**Version comaprison logic is**


.. code-block:: c

    if (Image Project != Device Project)
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


4. A type of the progress function: A function provided by the caller,
   intended to reflect the progress of the update.

.. code-block:: c

   typedef void (*igsc_progress_func_t)(IN uint32_t sent,
                                        IN uint32_t total,
                                        IN void *ctx);


5. Firmware update of the device: The function get buffer in memory
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

6. Function that implements version comparison logic, it returns
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

**Version comaprison logic is**


.. code-block:: c

    struct compare_version {
        uint16_t  major;
        uint16_t  minor;
        uint16_t  hotfix;
        uint16_t  build;
    };

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

The structure `igsc_image_oprom` is an opaque structure
representing used to hold paring state of the OPROM image
information.

  .. code-block:: c

    struct igsc_image_oprom;

4. Retrieve device device OPROM version for data and code.


  .. code-block:: c

    int igsc_device_oprom_version(IN  struct igsc_device_handle *handle,
                                  IN  uint32_t igsc_oprom_type,
                                  OUT struct igsc_oprom_version *version);

5. OPROM image Information retrieval:

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

      int igsc_image_oprom_type(IN struct igsc_image_oprom_info *img
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


  f. The function returns `TBD`: **found** if device is on the list of supported
     devices.

    .. code-block:: c

      int igsc_image_oprom_match_device(IN struct igsc_oprom_image *img,
                                        IN igsc_device_info *device)

  g. The function releases image handle `img`

    .. code-block:: c

      int igsc_image_oprom_relese(IN struct igsc_oprom_image *img);



6. Update option ROM partitions:

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

7. Function that implements version comparison logic, it returns
   one of values of `enum igsc_version_compare_result`

.. code-block:: c

   uint8_t igsc_oprom_version_compare(const struct igsc_oprom_version *image_ver,
                                      const struct igsc_oprom_version *device_ver);


2.6 Device Enumeration API
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
