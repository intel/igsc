/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2020 Intel Corporation
 */

#ifndef __IGSC_UTILS_H__
#define __IGSC_UTILS_H__

#define PACKAGE_LOG_NAME "IGSC"

#ifdef SYSLOG
    #ifdef _WIN32
       #include <stdio.h>
       #include <stdarg.h>
       #include <windows.h>
       #define DEBUG_MSG_LEN 1024
       static inline void debug_print(const char* fmt, ...)
       {
           char msg[DEBUG_MSG_LEN + 1];
           va_list varl;
           va_start(varl, fmt);
           vsprintf_s(msg, DEBUG_MSG_LEN, fmt, varl);
           va_end(varl);

           OutputDebugStringA(msg);
       }

       #define error_print(fmt, ...) debug_print(fmt, ##__VA_ARGS__)
       #define trace_print(fmt, ...) debug_print(fmt, ##__VA_ARGS__)

    #else /* WIN32 */

        #include <syslog.h>
        #define debug_print(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)
        #define error_print(fmt, ...) syslog(LOG_ERR, fmt, ##__VA_ARGS__)
        #define trace_print(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)

    #endif /* _WIN32 */

#else /* SYSLOG */
        #include <stdio.h>
        #define debug_print(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
        #define error_print(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
        #define trace_print(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#endif /* SYSLOG */

#if defined(DEBUG) || defined(_DEBUG)
#define gsc_debug(_fmt_, ...) \
    debug_print(PACKAGE_LOG_NAME ": (%s:%s():%d) " _fmt_, \
                __FILE__, __func__, __LINE__,  ##__VA_ARGS__)
#define gsc_trace(_fmt_, ...) \
    trace_print(PACKAGE_LOG_NAME ": (%s:%s():%d) " _fmt_, \
                __FILE__, __func__, __LINE__,  ##__VA_ARGS__)
#else
    #define gsc_debug(_x_, ...)
    #define gsc_trace(_x_, ...)
#endif /* PRINTS_ENABLE */

#define gsc_error(_fmt_, ...) \
    error_print(PACKAGE_LOG_NAME ": (%s:%s():%d) " _fmt_, \
                __FILE__, __func__, __LINE__, ##__VA_ARGS__)

#endif /* __IGSC_UTILS_H__ */
