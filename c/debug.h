#pragma once

#include <time.h>

// Allocate a thread-local variable for the thread name.
_Thread_local char *thread_name = "unknown";

#define DEBUG_SET_THREAD_NAME(name) thread_name = name

#define DEBUG(fmt, ...)                                                        \
	do {                                                                       \
		time_t t = time(NULL);                                                 \
		struct tm tm = *localtime(&t);                                         \
		fprintf(stderr,                                                        \
				"%d-%02d-%02dT%02d:%02d:%02d [%s] %s:%d DEBUG: " fmt "\n",     \
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,      \
				tm.tm_min, tm.tm_sec, thread_name, __FILE__, __LINE__,         \
				##__VA_ARGS__);                                                \
	} while (0)

#define print_ssl_error(msg)                                                   \
	do {                                                                       \
		unsigned long err = ERR_get_error();                                   \
		if (err != 0) {                                                        \
			char buf[256];                                                     \
			ERR_error_string_n(err, buf, sizeof(buf));                         \
			DEBUG("%s: %s", msg, buf);                                         \
		}                                                                      \
	} while (0)
