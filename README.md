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
    cmake -G Ninja -S . -B builddir
    ninja -v -C builddir
```

*Linux Debug version:*

```sh
    cmake -DSYSLOG:BOOL=OFF -DCMAKE_BUILD_TYPE=Debug -G Ninja -S . -B builddir
    ninja -v -C builddir
```


*Windows: (Visual Studio 2019)*

```sh
    cmake -G "Visual Studio 16 2019" -S . -B builddir
    cmake --build builddir --config Release
```

*Windows Debug version: (Visual Studio 2019)*

```sh
    cmake -G "Visual Studio 16 2019" -S . -B builddir
    cmake --build builddir --config Debug
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

`# igsc <partition> update|version  [--image <fw image file>]  [ --device <device>]`

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
