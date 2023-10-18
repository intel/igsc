/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020 Intel Corporation
 */

#ifndef __IGSC_MSVC_CONFIG_H__
#define __IGSC_MSVC_CONFIG_H__

#ifdef _MSC_VER
/* Disable: nonstandard extension used : zero-sized array in struct/union */
#pragma warning(disable:4200)
/* Disable: nonstandard extension used : nameless struct/union */
#pragma warning(disable:4201)
/* Disable: nonstandard extension used : bit field types other than int */
#pragma warning(disable:4214)
/* Disable: conditional expression is constant */
#pragma warning(disable:4127)

#define  mockable_static static
#define  mockable

#include <time.h>
static inline void gsc_localtime(const time_t* timer, struct tm* buf )
{
    localtime_s(buf, timer);
}

#endif /* _MSC_VER */

#endif /*__IGSC_MSVC_CONFIG_H__ */
