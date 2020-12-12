3. Command Line Tool
----------------------

The library provides a sample command line tool that demonstrate
usage of the library.

3.1 Usage:
~~~~~~~~~~

.. code-block:: sh

   igsc [-h] [-v]  <partition> <command> [options]

   *Supported partitions:*

       * *fwi* : GSC Firwmare
       * *oprom-code* : code (GOP) OPROM partition
       * *oprom-data* : data (VBT) OPROM partition

    *Flgas:*
       * -h | --help: displays usage and help for the tool
       * -v | --verbose:  verbose mode


3.2 GSC Firmware Update
~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Update device with the specific firmware image, in case the device is
   not supplied the tool will use the first available device.

   * options --allow-downgrade

.. code-block:: sh

    igsc fw update [optinons]  --image <fw image file> [--device <device>]

2. Retrieve the firmware version on the device,  in case the device is
   not supplied the tool will use the first available device.


.. code-block:: sh

    igsc fw version [--device <device>]

3. Retrieve the firmware version in the supplied image file.

.. code-block:: sh

    igsc fw version --image <fw image file>

3.3 OPROM Update
~~~~~~~~~~~~~~~~~

1. Update OPROM data (VBT) partition version, in case the device is
   not supplied the tool will use the first available device.

   * options --allow-downgrade

.. code-block:: sh

    igsc oprom update [options] [--device <device>] --image <oprom file>

2. Retrieve OPROM VBT (data) partition version

.. code-block:: sh

    igsc oprom-data version [--device <device>]

3. Retrieve OPROM VBT (data) partition version from the supplied data image file,

.. code-block:: sh

    igsc oprom-data version --image <oprom file>


4. Update OPROM code partition version, in case the device is
   not supplied the tool will use first available device.

   * options --allow-downgrade

.. code-block:: sh

    igsc oprom-code update [options] [--device <device>]  --image <oprom file>

5. Retrieve list of supported devices from the supplied OPROM data image,
   in form of subvendor and subdevice pci list.

.. code-block:: sh

    igsc oprom-code supported-devices --image <oprom file>

6. Retrieve OPROM code (GOP) partition version from the device, in case the device is
   not supplied the tool will use the first available device.

.. code-block:: sh

    igsc oprom-code version [--device <device>]

7. Retrieve OPROM code partition version from the supplied data image file

.. code-block:: sh

    igsc oprom-code version --image <oprom file>


3.4 Device enumeration
~~~~~~~~~~~~~~~~~~~~~~~

List all supported devices on the system. If --info flag is supplied also print
the firmware and OPROM partitions versions on each device.

.. code-block:: sh

    igsc list-devices [--info]


3.5 In-Field Repair
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: sh

    igsc ifr get-status --device /dev/meiX


.. code-block:: sh

    igsc ifr run-test --device /dev/meiX --tile [0|1|all] --test [scan|array]


