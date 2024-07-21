4. GSC Firmware Update API
---------------------------

This define interface between library and the FW.

The firmware update is performed over HECI2 interface over HECI client

============    ============================================================================
Client Name     GUID
------------    ----------------------------------------------------------------------------
GSC FW update    {0x87d90ca5, 0x3495, 0x4559, 0x81, 0x5, 0x3f, 0xbf, 0xa3, 0x7b, 0x8b, 0x79}
------------    ----------------------------------------------------------------------------
============    ============================================================================



4.1 GSC Firmware API
~~~~~~~~~~~~~~~~~~~~~

.. doxygengroup:: gsc-fw-api
   :project: igsc

1. Supported HECI commands

.. doxygengroup:: gsc-fw-api-hdr
   :project: igsc

2. Firmware version

This message is used to retrieve the overall version of the “DGFW Version”,
which is a version that reflects the overall combination of IPs
(including CSM/GSM FW Version, PUnit Patch Version, Dekel PHY Version etc.).
The DGFW Version will be part of the “IP Hash Manifest Extension” of the GSC FW Manifest
(commonly referred to as the “Mega Manifest”).
The format of the DGFW Version is still under discussion and is expected to change.

.. doxygengroup:: gsc_fw_api_ver
   :project: igsc

3. Update Protocol messages

.. doxygengroup:: gsc-fw-api-update
   :project: igsc
