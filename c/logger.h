#pragma once

#include <openssl/err.h>
#include <time.h>

#define DEBUG_SET_THREAD_NAME(name) thread_name = name

#define DEBUG(fmt, ...) LOGGER(fmt, "DEBUG", ##__VA_ARGS__)
#define ERROR(fmt, ...) LOGGER(fmt, "ERROR", ##__VA_ARGS__)
#define PERROR(fmt, ...)                                                                                               \
    do {                                                                                                               \
        unsigned long openssl_err = ERR_get_error();                                                                   \
        if (errno)                                                                                                     \
            LOGGER(fmt ": %s", "ERROR", ##__VA_ARGS__, strerror(errno));                                               \
        else if (openssl_err) {                                                                                        \
            char buf[256];                                                                                             \
            ERR_error_string_n(openssl_err, buf, sizeof(buf));                                                         \
            LOGGER(fmt ": %s", "ERROR", ##__VA_ARGS__, buf);                                                           \
        } else                                                                                                         \
            LOGGER(fmt, "ERROR", ##__VA_ARGS__);                                                                       \
    } while (0)

#define LOGGER(fmt, level, ...)                                                                                        \
    do {                                                                                                               \
        time_t t = time(NULL);                                                                                         \
        struct tm tm = *localtime(&t);                                                                                 \
        fprintf(stderr, "%d-%02d-%02dT%02d:%02d:%02d [%s] %s:%d " level ": " fmt "\n", tm.tm_year + 1900,              \
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, thread_name, __FILE__, __LINE__,          \
                ##__VA_ARGS__);                                                                                        \
    } while (0)
