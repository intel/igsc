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

    int igsc_device_info(IN  struct igsc_device_handle *handle,
                         OUT struct igsc_info_device *info, size_t *info_size);

2.4 GSC Firmware Update
~~~~~~~~~~~~~~~~~~~~~~~~

1. Firmware Version

The structure represents the device firmware version.

`TBD:` define how to compare the version

.. code-block:: c

    struct igsc_fw_version {
        char       Project[4];
        uint16_t   Hotfix;
        uint16_t   Build;
    };


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


2.5 OPROM Update API:
~~~~~~~~~~~~~~~~~~~~~

1. OPROM version is a string of 8 bytes.

  .. code-block:: c

    struct igsc_oprom_version {
      char version[8];
    };

  .. note::

    `TBD:` Define version comaprision.


2. OPROM Type

  .. code-block:: c

    enum igsc_oprom_type {
      IGSC_OPROM_DATA = 0,
      IGSC_OPROM_CODE = 1,
      IGSC_OPROM_MAX
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

5. Update option ROM partitions:

   The function gets a buffer in memory and sends it to the device.
   It calls progress function handler for each chunk it sends.

  .. code-block:: c

    int igsc_device_oprom_update(IN  struct igsc_device_handle *handle,
                                 IN  uint32_t igsc_oprom_type,
                                 IN  const uint8_t *buffer,
                                 IN  const uint32_t buffer_len,
                                 IN  igsc_progress_func_t progress_f,
                                 IN  void *ctx);

6. OPROM image Information retrieval:

   a. The function allocates and initializes an opaque
      structure `struct igsc_oprom_image` supplied
      OPROM image.

    .. code-block:: c

      int igsc_image_oprom_init(OUT struct igsc_oprom_image **img
                                IN  const uint8_t *buffer,
                                IN  uint32_t buffer_len);

  b. The function retrieve OPROM version from the OPROM image
     associated with the image handle `img`

    .. code-block:: c

      int igsc_image_oprom_version(IN struct igsc_oprom_image *img,
                                   OUT struct igsc_oprom_version *version);

  c. The function retrieves the type of the OPROM image associated with `img`.

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
