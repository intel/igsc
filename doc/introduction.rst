1. Introduction
----------------

The The Intel Graphics System Firmware Update Library (IGSCFUL) is
a pure C low level library that exposes a required API
to perform a firmware update of a particular Intel discrete
graphics device. The library utilized a cross platform library `metee`_ in
order to access the GSC (mei) device. GSC device is an extension of the
Intel discrete graphics device (dGFX).

The library can update GSC firmware itself, and as well as OPROM VBT
and the code (VBIOS, GOP).

The library provides retrieval of identity and version information from
both graphic device and supplied firmware or OPROM image as well as
function for firmware update of those images to the device.

.. _metee: https://github.com/intel/metee

1.2. GSC Firmware
~~~~~~~~~~~~~~~~~~


GSC Firmware is a firmware running on the graphics system controller.
It is responsible for system configuration, such as memory training
loading of other firmware components, as well as content protection
settings.

1.3 OPROM
~~~~~~~~~

An expansion ROM / option ROM is a firmware that resides on a PCIe device,
can be read by the host device and used to initialize or boot the device.
In Intel discrete graphics cards, the option ROM has two main roles:

  * Allows BIOS to use the display of the device – this is only relevant for
    platforms that use the card as their primary display.

  * Stores the VBT (Video BIOS table) – this is the table that holds the device
    specific display related manufacturing configurations.
    This data is used by both the option ROM and the dGFX driver.

1.4. Basic Flow
~~~~~~~~~~~~~~~

The application performing the firmware update opens a handle with device
associated /dev/meiX interface and get version and other identity information
from the device. Second, it will load the supplied firmware image and
retrieves same information from the loaded image.
Third,identity matching and version comparison to verify that the firmware
is matching and version is desired. Last it performs actual update
of the firmware.

1.5. Device enumeration
~~~~~~~~~~~~~~~~~~~~~~~

In order to enable firmware update of all devices in the system,
the library supports enumeration of graphics devices that are
subject to firmware and OPROM update, such as SG1 and DG1.

1.6. Integrations
~~~~~~~~~~~~~~~~~

  1. On Linux client platforms the library integrates with fwupd.org
     daemon via *igsc plugin. The *fwupd* daemon is commonly an integral part
     on modern Linux distributions.
  2. On servers platforms the library might be integrated with BMC based solution.

1.7. Command Line Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The project supplies sample command line tool that
support firmware and oprom update. It's a simple cross
platform utility.

1.8. Supported Devices
~~~~~~~~~~~~~~~~~~~~~~~~

.. Table: DGFX PCI DIDs

============    ======================
Device          DIDs
------------    ----------------------
DG1/SG1         0x4905 0x4906 0x4907
------------    ----------------------
ATS             0x0201
------------    ----------------------
DG2             0x4F80
------------    ----------------------
PVC             0x0BD0
============    ======================
