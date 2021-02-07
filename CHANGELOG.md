# IGSC FUL

## [v0.7.1] - 2021-11-02

### Fixed

cli: fix ifr run-test command with --device parameter


## [v0.7.0] - 2021-10-21

### Fixed

lib: increase read timeout
lib: ifr: remove redundant include from ifr.h
lib: include msvc config.h in enum files

### Changed

doc: add documentation for the new ifr api
ut: ifr: add unit tests for the new ifr get status command
ut: ifr: add unit tests for ifr memory ppr test command
ut: ifr: add unit tests for ifr array&scan command
cli: add new ifr get status command to cli
cli: add ifr memory ppr command to cli
cli: add ifr array&scan command to cli
cli: extend struct gsc_op to include up to 5 subcommands
lib: implement new ifr get status api
lib: implement ifr memory ppr test command
lib: implement new ifr array&scan test command api
lib: ifr: define new ifr command ids
lib: ifr: define api to new ifr get status command
lib: ifr: define api to ifr array&scan and memory ppr tests
lib: ifr: define new ifr heci commands
ut: add unit tests for "get memory ppr status"
ut: add unit tests for "get number of memory errors"
doc: add documentation of "get number of memory errors" api
doc: add documentation for "get memory ppr status" api
ut: remove obsolete definition of read_ifr_file
cli: gfsp: implement "get memory ppr status" cli command
lib: gfsp: implement "get memory ppr status" api
lib: gfsp: define "get memory PPR status" api
lib: gfsp: add "get memory PPR status" heci message definitions
cli: gfsp: implement "get number of memory errors" cli command
lib: gfsp: implement "get number of memory errors" api
lib: gfsp: define "get number of memory errors" api

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
