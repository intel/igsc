# IGSC FUL

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

1. doc: add no_update flow to the documenation
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
