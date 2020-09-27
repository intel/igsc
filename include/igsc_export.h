/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020 Intel Corporation
 */

#ifndef __IGSC_EXT_H__
#define __IGSC_EXT_H__

#if defined (_WIN32) || defined (_WIN64)
  #ifdef IGSC_DLL_EXPORTS
    #define IGSC_EXPORT __declspec(dllexport)
  #else
    #define IGSC_EXPORT __declspec(dllimport)
  #endif
#else
  #ifdef IGSC_DLL_EXPORTS
    #define IGSC_EXPORT __attribute__((__visibility__("default")))
  #else
    #define IGSC_EXPORT
  #endif
#endif
#endif /* __IGSC_EXT_H__ */
