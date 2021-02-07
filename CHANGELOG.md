# IGSC FUL

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
2. cmake: enchance metee search

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
