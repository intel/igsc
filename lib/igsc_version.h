/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2020 Intel Corporation
 */
#ifndef __IGSC_VERSION_H__
#define __IGSC_VERSION_H__

#include <stdint.h>

#pragma pack(1)

struct gsc_fwu_version {
	uint16_t  major;
	uint16_t  minor;
	uint16_t  hotfix;
	uint16_t  build;
};

struct gsc_fwu_external_version {
	char     project[4];
	uint16_t hotfix;
	uint16_t build;
};

#pragma pack()

#endif /* !__IGSC_VERSION_H */
