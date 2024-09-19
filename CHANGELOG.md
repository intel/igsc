# IGSC FUL

## [v0.9.4] - 2024-09-19

### Added
1. lib: add timestamps to logs
2. cli: implement read firmware status register in cli
3. lib: implement read firmware status register library API
4. cli: print error message when device iterator failed

### Changed
1. lib: don't suppress metee error messages in debug mode

### Fixed
1. igsc: lib: fix device enumeration in linux

## [v0.9.3] - 2024-07-23

### Fixed
1. conan: fix typo in conan.cmake
2. lib: fix typos in the library
3. doc: fix typos in api documentation
4. ci: fix-up codespell configuration
5. ut: check for null before strlen in test_strdup
6. lib: fix igsc_get_log_callback_func prototype

### Added
1. lib: add soc4 hardware sku

## [v0.9.2] - 2024-07-15

### Fixed
1. lib: fix parameter check in igsc_gfsp_heci_cmd

## [v0.9.1] - 2024-07-11

### Added
1. cli: add a retry on igsc_device_fwdata_version2

### Fixed
1. ut: fix gfsc heci generic command test
2. lib: fix response size check
3. cli: fix possible memory leak in fwupd_strerror

### Changed
1. lib: expand firmware update errors handling

## [v0.9.0] - 2024-06-20

### Added
1. lib: adding support to print IGSC debug logs via callback function
2. lib: add dedicated arb svn support
3. cli: add dedicated arb svn support
4. tests: add dedicated arb svn support

### Fixed
1. lib: drop version check from igsc_device_fwdata_update
2. cli: fix fw data update check

## [v0.8.21] - 2024-05-26

### Changed
1. lib: pop the metee library version to 4.1.0 in conan
2. lib: set verbose metee mode

## [v0.8.20] - 2024-05-22

### Fixed
1. lib: ignore return value of write on fwu_end command

## [v0.8.19] - 2024-05-17

### Added
1. cli: implement retry mechanism when device is busy
2. lib: return busy indication on special connect failures

### Fixed
1. lib: fix fwdata heci response struct

### Removed
1. Doxygen: drop HTML timestamp

## [v0.8.18] - 2024-02-20

### Added
1. doc: add documentation for arb svn library api
2. ut: add tests for arb svn API
3. cli: implement arb svn commands in cli
4. lib: implement arb svn library API

### Fixed
1. cli: fix description of the device in oem version command
2. doc: fix doc generation errors and warnings
3. CHANGELOG: fix item numbering

## [v0.8.17] - 2024-01-03

### Added

1. docs: add igsc_device_update_late_binding_config
2. ut: add test for igsc_device_update_late_binding_config
3. cli: add late-binding command line option
4. lib: implement igsc_device_update_late_binding_config api
5. lib: add general gfsp heci command api
6. cli: add gfsp generic command to cli
7. ut: add tests for general gfsp heci cmd library api
8. doc: add generic gfsp heci message api documentation
9. README: add testing compilation explanation

### Fixed
1. lib: make OEM version an array of uint_8 instead of char
2. ut: fix handle initialization

### Changed
1. cli: print firmware status as hex form


## [v0.8.16] - 2023-10-31

### Added
1. cli: add delay between the update and get firmware version

## [v0.8.15] - 2023-10-24

### Changed
1. conan: use metee 3.2.4

### Fixed
1. lib: wait for reset at the end of the update
2. lib: wait for background operation to finish

## [v0.8.14] - 2023-09-20

### Fixed
1. gitignore: ignore VisualStudio directory
2. ci: fix clang-tidy reporting

### Changed
1. cli: do not use relative includes
2. cli: the global variables used only in one c file should be static
3. lib: move chunk_size declaration to its scope in gsc_update
4. ut: update cmake for new cmocka packaging

### Added
1. qb: copy PDB file to output and generate public pdb
2. Windows: generate pdb in Release build

## [v0.8.13] - 2023-06-13

### Fixed
1. lib: disconnect on failure in gsc_driver_init

### Changed
1. lib: suppress specific errors during firmware reset
2. lib: quiet libmei errors around firmware reset flow
3. conan: use metee 3.2.3

## [v0.8.11] - 2023-04-30

### Added
1. build: sign dll
2. lib: add trace log level
3. lib: implement log levels
4. cli: set library log level in verbose mode
5. cli: add trace mode to cli

### Changed
1. lib: expand windows logs
2. lib: move received and sent data prints from debug to trace

### Fixed
1. lib: fix debug messages that should have been printed as errors
2. lib: fix printf format specifiers

### Removed
1. lib: remove check for version in get_hw_config
2. ut: remove get version from hw_config tests
3. cli: don't check hw_config when firmware does not support it
4. cli: remove unnecessary did enforcement check
5. lib: drop ifdef DEBUG around log prints

## [v0.8.9] - 2023-02-12

### Changed
1. power: udev: demote error print in power/control open failure

### Fixed
1. ut: fix struct initializations for msvc
2. ut: igsc_test: no need to alloc handle for ctx
3. ut: fix the igsc_test to check for the correct return value
4. lib: check parameters of library api functions
5. lib: image_oprom_parse_cpd: prevent widening integer overflow
6. cli: do_firmware_update: remove unnecessary continue statement
7. lib: image_oprom_get_buffer check the assigned values
8. lib: check return value of gsc_image_fw_version function
9. lib: gsc_fwu_is_in_progress: don't assign unused value
10. cli: remove assignments of values that are logically unused
11. lib: initialize scalar variables

## [v0.8.8] - 2023-02-14

### Added
1. lib: add timeout for oprom update to finish
3. tests: add firmware update unit test

### Changed
1. lib: reduce frequency of calling progress function

### Fixed
1. lib: sleep unconditionally during firmware updates cycles
2. lib: check the reserved fields of fwu response messages header
3. tests: initialize firmware version before retrieving it

## [v0.8.7] - 2023-01-09

### Added

1. lib: add retries on initialization
2. tests: add test for retries in init

### Changed

1. conan: use MeTee 3.1.5

### Fixed

1. README: fix documentation link to igsc_api.rst
2. README: add explanation how to run windows build
3. README: expand metee download explanations

## [v0.8.6] - 2022-12-20

### Added

1. lib: add timeout for update to finish
2. lib: ifr: implement get health indicator api
3. doc: add documentation for get memory health indicator api
4. ut: add unit tests for health indicator api
5. cli: implement get memory health indicator in cli
6. lib: ifr: define get memory error mitigation status heci messages

### Fixed

1. cli: fix description in usage help


## [v0.8.5] - 2022-09-06

### Added

1. doc: add documentation of oem, ifr and psc versions retrieval
2. ut: add tests for oem, ifr and psc version api
3. cli: implement retrieve ifr version in cli
4. cli: implement retrieve psc version in cli
5. lib: retrieve oem and psc binary versions
6. lib: define mkhi get version heci messages
7. cli: implement retrieval of oem version
8. lib: implement retrieval of oem version
9. lib: define oem, psc and ifr version api
10. lib: implement read file functionality
11. lib: define read file heci commands
12. lib: move mkhi header definition from ifr.h to igsc_heci.h
13. cli: retrieve firmware version before oprom and fw data update

### Fixed

1. lib: fix firmware data version retrieval
2. ci: fix docker user id for lms-ubuntu:19.10
3. lib: fix fw data heci version response handling

## [v0.8.4] - 2022-07-03

### Added

1. README: mention libudev dependency
2. qb: add linux build script
3. ci: add quckbuild windows build script
4. cmake: add windows presets
5. cmake: add option to download dependencies from conan
6. cmake: enhance metee search
7. add error messages prints for unsupported hw config
8. src: add check of the versions after update
9. lib: add check of the versions after update
10. ci: enable tests compile
11. ci: print docker name also for cmake
12. ci: add ctest to compilation tasks
13. lib: add UNUSED_VAR cross platform macro

### Fixed

1. fix device ids extension number
2. conan: clean conanfile
3. cli: fix a memory leak in do_ifr_get_repair_info
4. lib: fix compilation warnings of ISO C90
5. lib: fix unsigned formats in print statements
6. cli: make fw and fw data versions prints more readable
7. tests: cmake: fix dependencies
8. ut: power_stubs.h fix includes
9. cmake: metee: the find package has to match the case
10. ci: move to self-hosted runners to other resource
11. ci: rename job clang-compile to compile

### Removed

1. lib: remove enable_enum option in cmake and meson

## [v0.8.3] - 2022-05-10

### Added

1. lib: enum: windows: add domain (segment) retrieval

### Fixed

1. lib: enum: windows: fix device bdf retrieval

## [v0.8.2] - 2022-04-18

### Added

1. lib: set power control to on during operations

## [v0.8.1] - 2022-03-22

### Changed

1. conan: clean conanfile
2. lib: remove enable_enum option in cmake and meson
3. lib: extend igsc_hw_config_to_string

### Fixed

1. cli: fix return value treatment of match device function
2. lib: fix get device config function
3. lib: fix fw data heci version response handling
4. cli: fix a memory leak in do_ifr_get_repair_info
5. lib: fix compilation warnings of ISO C90
6. ut: power_stubs.h fix includes
7. tests: cmake: fix dependencies
8. lib: fix unsigned formats in print statements
9. cli: make fw and fw data versions prints more readable
10. lib: enum: windows: fix device bdf retrieval
11. cli: fix handling of match function return value
12. ut: fix image type in the test setup
13. lib: fix structures definition coding style
14. lib: fix gfsp_heci_validate_response_header usage
15. lib: fix error message in gfsp response validation
16. lib: gsc_fwu_get_version() initialize received_len
17. ut: fix uninitialized oprom_image structure in tests

### Added

1. src: add check of the versions after update
2. lib: add check of the versions after update
3. README: mention libudev dependency
4. lib: add UNUSED_VAR cross platform macro
5. cli: add error messages prints for unsupported hw config
6. lib: add error messages prints for unsupported hw config
7. lib: set power control to on during operations
8. lib: add debug prints for 4ids extension processing
9. lib: implement special case for images with no device extensions
10. cli: add oprom code update devId enforcement check
11. lib: add igsc_image_oprom_code_devid_enforced()
12. ut: add cli unit-tests for supported-devices
13. ut: add tests for the 4ids library functions
14. cli: implement supported-devices flag for oprom images
15. lib: add oprom image has 4ids or 2ids extension API
16. lib: add oprom image 4ids and 2ids extension query functions
17. lib: implement oprom 4ids library api
18. lib: implement oprom 4ids parsing helper functions
19. lib: parse 4ids supported device list extension
20. lib: use legacy device extension for oprom data only
21. lib: define 4-ids extension structures
22. lib: update the oprom code devId enforcement flag
23. lib: add oprom code device ids flag to heci reply
24. lib: add definitions of the new apis for 4-IDs oprom
25. lib: define the oprom device info structure with 4 IDs
26. cli: print status from fw in non-verbose mode
27. README: recommend visual studio 2019
28. cmake: add option to static build
29. cli: add ecc config commands
30. lib: implement ecc config commands
31. lib: add heci definitions for ecc config commands

## [v0.8.0] - 2022-07-10

Note: non backward compatible change (num_of_tiles to max_num_of_tiles)

### Changed

1. cli: rename num_of_tiles to max_num_of_tiles
2. lib: rename num_of_tiles to max_num_of_tiles
3. cli: report error on extra argument
4. lib: update ifr bitmaps definitions

### Fixed

1. cli: make print_mem_ppr_status output readable
2. cli: make mem_ppr_test output readable
3. cli: make get_status_ext output readable
4. cli: ifr: make array_scan_test output readable
5. lib: fix return value doc of the igsc_device_iterator_destroy
6. lib: ifr: rewords error messages and drop redundant debug
7. cli: remove redundant calls to get subsystem DID/VID
8. cli: remove redundant print from run_ifr_test
9. ut: initialize buffer in test function

### Added

1.  cli: add missing newline in get_mem_ppr_status
2.  doc: add info about multithreading support
3.  doc: add documentation of get ifr repair info and count tiles APIs
4.  ut: add tests for ifr get repair info and count tiles commands
5.  cli: add ifr get repair info and count tiles commands to cli
6.  lib: add ifr get tile repair info and count tiles library APIs
7.  lib: add heci definitions for get ifr info commands
8.  lib: update ifr bitmaps definitions
9.  .gitignore: add cpack intermediate files
10. docs: .gitignore: add auto generated Doxygen

## [v0.7.0] - 2022-07-01

### Added

1.  ci: add codespell configuration files
2.  doc: add documentation for the new ifr api
3.  ut: ifr: add unit tests for the new ifr get status command
4.  ut: ifr: add unit tests for ifr memory ppr test command
5.  ut: ifr: add unit tests for ifr array&scan command
6.  cli: add new ifr get status command to cli
7.  cli: add ifr memory ppr command to cli
8.  cli: add ifr array&scan command to cli
9.  cli: extend struct gsc_op to include up to 5 subcommands
10. lib: implement new ifr get status api
11. lib: implement ifr memory ppr test command
12. lib: implement new ifr array&scan test command api
13. lib: ifr: define api to new ifr get status command
14. lib: ifr: define api to ifr array&scan and memory ppr tests
15. lib: ifr: define new ifr heci commands
16. ut: add unit tests for "get memory ppr status"
17. ut: add unit tests for "get number of memory errors"
18. doc: add documentation of "get number of memory errors" api
19. doc: add documentation for "get memory ppr status" api
20. cli: gfsp: implement get memory ppr status cli command
21. lib: gfsp: implement get memory ppr status api
22. lib: gfsp: add get memory PPR status heci message definitions
23. lib: gfsp: define "get memory PPR status" api
24. cli: gfsp: add get number of memory errors cli command
25. lib: gfsp: define get number of memory errors API
26. cmake: add windows presets
27. cmake: add option to download dependencies from conan


### Fixed

1. cli: fix ifr run-test command with --device parameter
2. lib: increase read timeout
3. lib: ifr: remove redundant include from ifr.h
4. lib: include msvc config.h in enum files
5. lib: adjust sku tag naming
6. ut: oprom update on bad type return invalid param error
7. lib: ifr: remove redundant include from ifr.h



### Changed

1. ut: remove obsolete definition of read_ifr_file
2. cmake: enhance metee search

## [v0.6.0] - 2022-02-20

### Added

1. doc: add documentation of the get subsystem ids functionality
2. tests: add unit-test for subsystems ids functions
3. cli: add device info update
4. lib: implement get subsystem ids library function
5. lib: add get subsystem ids heci messages definitions
6. doc: add documentation for iaf psc partition update api
7. doc: add firmware data update api documentation

### Fixed

1. lib: fix wrong handling of return values in subsystem ids
2. lib: release fwdata image in igsc_device_fwdata_update()
3. lib: add more meaningful comments for enum gsc_fwu_heci_command_id
4. doc: fix library documentation of return values
5. doc: separate the ifr into higher level section
6. doc: little fixes in igsc_api

## [v0.5.0] - 2022-02-01

### Added

1.  tests: add fw data update tests
2.  tests: add force update library function tests
3.  cli: add force update option to fw update
4.  lib: add force update bit flag to the lib
5.  cli: add fw data update to cli
6.  lib: add signed in field data update to the library
7.  lib: add library API for the GSC In-Field Data Update
8.  lib: support the second firmware reset in CP mode

### Fixed

1.  tests: fix layout_parse function in firmware parser tests
2.  lib: fix typos in comments in igsc_lib.h
3.  lib: fix hw config comparison in library


## [v0.4.0] - 2022-01-30

### Added
1. lib: send no update message at the end of firmware update
2. lib: retrieve hw configuration from the device
3. lib: add igsc_fw_hw_config_compatible() function
4. cli: add hw config option to cli

### Fixed

1. Fix VERSION file


## [V0.3.0] - 2022-01-17

### Added

1. Add accelrator fabric PSC update
2. In field repair command support
3. Fix spelling of word 'firmware'


## [v0.2.6] - 2021-09-02

### Fixed

cli: print device BDF as a hexadecimal numbers
lib: udev: parse device BDF as hexadecimal
doc: fix igsc documentation

## [v0.2.5] - 2021-08-30

### Added

1. scripts: add vscode build script

### Fixed

1. lib: check integer overflow in oprom parser
2. lib: try reconnect in a loop after firmware reset
3. lib: fix the gsc_msleep function
4. cli: fix debug print of sent data hex dump

## [v0.2.4] - 2021-06-14

### Added

1. cmake: add package config helper

### Fixed

1. cli: fix oprom update error handling
2. lib: fix error value for mismatch of oprom image type and request


## [v0.2.3] - 2021-06-06

### Added

1. lib: use generic BIT macro

### Fixed

1.  oprom: fix type size comparison issue in oprom_parser.c
2.  cli: add a message when permission denied
3.  lib: add permission denied error code to the library
4.  lib: restart firmware update in case of an error
5.  lib: add timeout teewrite and teewrite
6.  cli: prefix the firmware version in print
7.  lib: CMake: require UDev library and header on Linux
8.  CMake: set DEBUG defines in Debug mode
9.  cli: oprom: fix print if good devid is not found in the image
11. oprom: use %d for uint32_t in debug prints


## [v0.2.2] - 2021-03-21

### Added

1. doc: add no_update flow to the documentation 
2. lib: send no update message at the end of firmware update
3. lib: generalize image update flow
4. lib: export tee handlers functions to the internal header

### Fixed


## [v0.2.1] - 2020-12-22

### Added

1. lib: add igsc_internal.h with struct igsc_lib_ctx
2. doc: add firmware status code retrieval functions
3. cli: add firmware status print in verbose mode
4. lib: add return code from the firmware HECI messages
5. lib: add heci buffer trace (in debug code)
6. Add Apache 2 license file

### Fixed

1. metee.wrap use https instead of ssh for metee
2. cmake: drop REQUIRED for metee find_library
3. merge igsc_export.h into igsc_lib.h
4. README.md use uniform name for build directory
5. Add missing stack protection compilation flags
6. test: fix pointer sign conversion
7. Fix uninitialized variable warning in oprom_parser

# IGSC FUL

## [v0.2.0] - 2020-10-08

### Added

1. get image type API

### Fixed

1. Fixed few spelling errors

## [v0.1.4] - 2020-09-21

### Added

1. Add requirements and tests

### Fixed

1. cmake: add security compilation flags

### Changed
1. lib: make enumeration part of the library optional
2. build: make cli binary build to be optional
3. build: remove dependency on cmake in meson

## [v0.1.3] - 2020-08-31

### Added

### Fixed

1. cli: add more error messages
2. oprom: allow update when device version's major is 0

### Changed

## [v0.1.2] - 2020-08-24

### Added

### Fixed

1. cli: check for NULL returned from calloc()

### Changed

## [v0.1.1] - 2020-08-20

### Added

### Fixed

1. cli: fix segmentation fault in firmware update with broken image
2. cli: change progress bar in oprom to display percentage only

### Changed

1. Unit tests improvements.
2. Simplify token matching in cli

## [v0.1.0] - 2020-08-16

### Added

1. cli: Add progress function with percentage only
2. cli: Add --quiet option.
3. cli: Add more error messages.
4. cli: list devices supported by the OPROM image data
5. lib: Add firmware version comparison.
6. lib: Add oprom version comparison
7. lib: Retrieve BDF of the device
6. lib: Update udev matching to new driver API.

### Fixed

1. cli: print usage if there is no command after -q or -v option
3. cli: fix a progress bar issue
2. README: specify debug and release configurations

### Changed

1. Unit tests improvements.
2. Simplify token matching in cli

## [v0.0.9] - 2020-07-15

Enable update from a combined OPROM image

### Added

1. Added possibility to update OPROM from a combined image.
2. Verify OPROM data partition is supported by the device
   via subsystem vendor and device id
3. Implement igsc_device_init_by_handle()
4. Implement igsc_device_get_device_info()

### Fixed

1. Fix progress bar

### Changed

1. Remove enums from the API
2. UT cleanups

## [v0.0.8] - 2020-07-06

First internal release.

### Added

1. OPROM update API
2. Updated documentation

### Fixed

1. Linux: Reconnect after update.

### Changed
