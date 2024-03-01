#pragma once

#include <openssl/err.h>
#include <time.h>

// Allocate a thread-local variable for the thread name.
_Thread_local char *thread_name = "unknown";

#define DEBUG_SET_THREAD_NAME(name) thread_name = name

#define DEBUG(fmt, ...) LOG_PRINT(fmt, "DEBUG", ##__VA_ARGS__)
#define PERROR(fmt, ...)                                                       \
	do {                                                                       \
		unsigned long openssl_err = ERR_get_error();                           \
		if (errno)                                                             \
			LOG_PRINT(fmt ": %s", "ERROR", ##__VA_ARGS__, strerror(errno));    \
		else if (openssl_err) {                                                \
			char buf[256];                                                     \
			ERR_error_string_n(openssl_err, buf, sizeof(buf));                 \
			LOG_PRINT(fmt ": %s", "ERROR", ##__VA_ARGS__, buf);                \
		} else                                                                 \
			LOG_PRINT(fmt, "ERROR", ##__VA_ARGS__);                            \
	} while (0)

#define LOG_PRINT(fmt, level, ...)                                             \
	do {                                                                       \
		time_t t = time(NULL);                                                 \
		struct tm tm = *localtime(&t);                                         \
		fprintf(stderr,                                                        \
				"%d-%02d-%02dT%02d:%02d:%02d [%s] %s:%d " level ": " fmt "\n", \
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,      \
				tm.tm_min, tm.tm_sec, thread_name, __FILE__, __LINE__,         \
				##__VA_ARGS__);                                                \
	} while (0)
