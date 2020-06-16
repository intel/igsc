# Intel(R) Graphics System Controller Firmware Update Library (IGSC FU)
--------------------------------------------------------------------------

## Introduction
---------------

### Documentation

[API Documentation](https://mesw.gitlab-pages.devtools.intel.com/fwupd/fwupd-test/ "API Documentation")

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

## Command Line Tool Usage
--------------------------

`# igsc update  <fw image file> [<device>]`

`# igsc version [<device>]`

`# igsc image-version <fw image file>`
