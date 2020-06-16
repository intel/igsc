3. Command Line Tool
----------------------

The library provides a sample command line tool
that demonstrate usage of the library


3.1 GSC firmware handling
~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Update device with the specific firmware image

   * options --allow-downgrade

.. code-block:: sh

    igsc fw update [optinons]  --image <fw image file> --device [<device>]

2. Retrieve the firmware version on the device.

.. code-block:: sh

    igsc fw version [--device <device>]

3. Retrieve the firmware version in the supplied image file

.. code-block:: sh

    igsc fw version --image <fw image file>

3.2 OPROM handling
~~~~~~~~~~~~~~~~~~~

1. Update OPROM VBT (data) partition version

   * options --allow-downgrade

.. code-block:: sh

    igsc oprom-data update [options] [--device <device>]

2. Retrieve OPROM VBT (data) partition version

.. code-block:: sh

    igsc oprom-data version [--device <device>]

3. Retrieve OPROM VBT (data) partition version from the supplied data image file

.. code-block:: sh

    igsc oprom-data version --image <oprom file>


4. Update OPROM code partition version

   * options --allow-downgrade

.. code-block:: sh

    igsc oprom-code update [options] [--device <device>]

5. Retrieve OPROM code partition version from the device

.. code-block:: sh

    igsc oprom-code version [--device <device>]

6. Retrieve OPROM code partition version from the supplied data image file

.. code-block:: sh

    igsc oprom-code version --image <oprom file>


3.3 Device enumeration
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: sh

   igsc list-devices
