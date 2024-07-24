/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2019-2024 Intel Corporation
 */
# ifndef __IGSC_TEST_STRDUP_H___
#define __IGSC_TEST_STRDUP_H___
char *test_strdup(const char *s)
{
    if (s == NULL)
    {
        return NULL;
    }
    size_t len = strlen(s);
    char *d = calloc(1, len + 1);
    if (d == NULL)
    {
        return NULL;
    }
    memcpy(d, s, len + 1);
    return d;
}
#endif /* __IGSC_TEST_STRDUP_H__ */
