# Intel(R) Graphics System Controller Firmware Update Library (IGSC FU)
--------------------------------------------------------------------------

## Introduction
---------------

### Documentation

[API Documentation](https://mesw.gitlab-pages.devtools.intel.com/fwupd/igsc/ "API Documentation")

## Build

### Requirements:

  * MeTee: https://github.com/intel/metee

Both cmake and meson build framework are supported.

### CMake

**Example:**

*Linux:*

```sh
    cmake -DSYSLOG:BOOL=OFF -G Ninja -S . -B builddir
    ninja -v -C buildir
```

*Windows:*

```sh
    cmake -G "Visual Studio 15 2017" -S . -B buildir
    cmake --build builddir --config Release
```

### meson

**Example:**

```sh
    meson setup builddir/
    meson configure -Dsyslog=true builddir
    ninja -v -C builddir/
```

## Command Line Tool Usage Example:
--------------------------

`# igsc <partitin> update|version  [--image <fw image file>]  [ --device <device>]`

**Example:**

`# igsc fw version --device /dev/mei2

`# igsc oprom-data update --image <fw image file>`

### Library and CLI Version

The library is versioned according [semantic versioning 2.0.0](https://semver.org/ "semantic versioning")

*MAJOR.MINOR.PATCH-<extension>, incrementing the:

 * *MAJOR* incompatible API changes,
 * *MINOR* add functionality in a backwards compatible manner
 * *PATCH* version when you make backwards compatible bug fixes.
 * *Extension Label* git shortened commit hash or other extension.
