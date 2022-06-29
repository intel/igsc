# IGSC FUL

## [v0.8.4] - 2022-07-03

### Added

1. README: mention libudev dependency
2. qb: add linux build script
3. ci: add quckbuild windows build script
4. cmake: add windows presets
5. cmake: add option to download dependencies from conan
6. cmake: enchance metee search
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

1. lib: extend igsc_hw_config_to_string
2. lib: add comment describing oprom update logic
3. lib: use legacy device extension for oprom data only
4. lib: define 4-ids extension structures
5. lib: update the oprom code devId enforcement flag
6. cli: print status from fw in non-verbose mode
7. README: recommend visual studio 2019
8. cmake: add option to static build

### Fixed

1. cli: fix handling of match function return value
2. ut: fix image type in the test setup
3. lib: fix struct definition coding style
4. lib: fix gfsp_heci_validate_response_header usage
5. lib: fix error message in gfsp response validation

### Added
1. lib: add debug prints for 4ids extension processing
2. lib: implement special case of no device extensions
3. cli: add oprom code update devId enforcement check
4. lib: add igsc_image_oprom_code_devid_enforced() api
5. ut: add cli unit-tests for 4ids functionality
6. ut: add tests for the 4ids library functions
7. cli: implement cli changes for handling 4ids images
8. lib: add oprom image has 4ids or 2ids extension api
9. lib: add oprom image 4ids and 2ids extension functions
10. lib: implement oprom 4ids library api
11. lib: implement oprom 4ids parsing helper functions
12. lib: parse 4ids supported device list extension
13. lib: define 4-ids extension structures
14. lib: define 4-ids extension structures
15. lib: add oprom code device ids flag to heci reply
16. lib: add definitions of the new apis for 4-IDs oprom
17. lib: define the oprom device info structure with 4 IDs
18. doc: add ecc config commands
19. test: add tests for ecc config
20. cli: add ecc config commands
21. lib: implement ecc config commands
22. lib: add heci definitions for ecc config commands

## [v0.8.0] - 2022-02-22

Note: non backward compatible change (num_of_tiles to max_num_of_tiles)

### Changed

1. cli: rename num_of_tiles to max_num_of_tiles
2. lib: rename num_of_tiles to max_num_of_tiles

### Fixed

1. cli: remove redundant print from run_ifr_test
2. cli: remove redundant calls to get subsystem DID/VID
3. lib: fix documentation of the igsc_device_iterator_destroy function
4. lib: fix debug and error messages
5. cli: fix the extra arguments issue
6. doc: fix spelling
7. cli: add missing newline in get_mem_ppr_status
8. doc: fix spelling
9. cli: make print_mem_ppr_status output readable
10. cli: make mem_ppr_test output readable
11. cli: make get_status_ext output readable
12. cli: make array_scan_test output readable

### Added

1. cli: add ifr get repair info and count tiles commands to cli
2. lib: add ifr get tile repair info and count tiles library apis
3. doc: add documentation of get ifr repair info and count tiles apis
4. doc: add info about multithreading support

## [v0.7.1] - 2021-11-02

### Fixed

1. cli: fix ifr run-test command with --device parameter

## [v0.7.0] - 2021-10-21

### Fixed

1. lib: increase read timeout
2. lib: ifr: remove redundant include from ifr.h
3. lib: include msvc config.h in enum files

### Changed

1. doc: add documentation for the new ifr api
2. ut: ifr: add unit tests for the new ifr get status command
3. ut: ifr: add unit tests for ifr memory ppr test command
4. ut: ifr: add unit tests for ifr array&scan command
5. cli: add new ifr get status command to cli
6. cli: add ifr memory ppr command to cli
7. cli: add ifr array&scan command to cli
8. cli: extend struct gsc_op to include up to 5 subcommands
9. lib: implement new ifr get status api
10. lib: implement ifr memory ppr test command
11. lib: implement new ifr array&scan test command api
12. lib: ifr: define new ifr command ids
13. lib: ifr: define api to new ifr get status command
14. lib: ifr: define api to ifr array&scan and memory ppr tests
15. lib: ifr: define new ifr heci commands
16. ut: add unit tests for "get memory ppr status"
17. ut: add unit tests for "get number of memory errors"
18. doc: add documentation of "get number of memory errors" api
19. doc: add documentation for "get memory ppr status" api
20. ut: remove obsolete definition of read_ifr_file
21. cli: gfsp: implement "get memory ppr status" cli command
22. lib: gfsp: implement "get memory ppr status" api
23. lib: gfsp: define "get memory PPR status" api
24. lib: gfsp: add "get memory PPR status" heci message definitions
25. cli: gfsp: implement "get number of memory errors" cli command
26. lib: gfsp: implement "get number of memory errors" api
27. lib: gfsp: define "get number of memory errors" api

## [v0.6.0] - 2021-09-02

### Added

1. doc: add documentation of the get subsystem ids functionality
2. tests: add unit-test for subsystems ids functions
3. cli: add device info update
4. lib: implement get subsystem ids library function
5. lib: add more meaningful comments for enum gsc_fwu_heci_command_id
6. lib: add get subsystem ids heci messages definitions
7. doc: add documentation for iaf psc partition update api
8. doc: add signed in-field firmware data update api documentation

### Fixed

1. cli: print device BDF as a hexadecimal numbers
2. lib: udev: parse device BDF as hexadecimal
3. lib: fix wrong handling of return values
4. cli: fix unreachable code issues in cli
5. lib: release fwdata image in igsc_device_fwdata_update()
6. doc: fix library documentation of return values
7. doc: fix ifr indentation in the documentation
8. doc: fix igsc documentation

## [v0.5.0] - 2021-07-21

### Added

1.  tests: add fw data update tests
2.  tests: add force update library function tests
3.  cli: add force update option to fw update
4.  lib: add force update bit flag to the lib
5.  cli: add fw data update to cli
6.  lib: add signed in field data update to the library
7.  lib: add library API for the GSC In-Field Data Update
8.  lib: support the second firmware reset in CP mode
9.  cmake: add package config helper
10. cli: add a message when permission denied
11. lib: add permission denied error code to the library
12. lib: add timeout teewrite and teewrite
13. ci: add Debug Windows build
14. CMake: set DEBUG defines in Debug mode

### Fixed

1.  lib: check integer overflow in oprom parser
2.  tests: fix layout_parse function in firmware parser tests
3.  lib: fix typos in comments in igsc_lib.h
4.  lib: try reconnect in a loop after firmware reset
5.  lib: fix the gsc_msleep function
6.  cli: fix debug print of sent data hex dump
7.  lib: fix hw config comparison in library
8.  cli: fix oprom update error handling
9.  lib: fix error value for mismatch of oprom image type and request
10. oprom: fix type size comparison issue in oprom_parser.c
11. ci: fix hw config compitability logic and print-outs
12. lib: CMake: require UDev library and header on Linux
13. lib: restart firmware update in case of an error
14. cli: oprom: fix print if good devid is not found in the image
15. fix CHANGELOG spelling

### Changed

1.  lib: replace the 512/128 SKU names with SOC1/SOC2
2.  cli: prefix the firmware version in print

## [v0.4.0] - 2021-04-12

### Added
1. lib: send no update message at the end of firmware update
2. lib: retrieve hw configuration from the device
3. lib: add igsc_fw_hw_config_compatible() function
4. cli: add hw config option to cli

### Fixed

1. lib: oprom: use %d for uint32_t in debug prints
2. lib: use generic BIT macro

## [v0.3.1] - 2021-02-07

### Added

### Fixed

1. lib: remove driver reconnect after iaf psc update
2. lib: fix psc update

## [v0.3.0] - 2021-01-17

### Added

1. Add accelrator fabric PSC update
2. In field repair command support

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
