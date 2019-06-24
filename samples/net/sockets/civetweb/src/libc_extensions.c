#include <zephyr.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "libc_extensions.h"

#define FN_MISSING() printf("[IMPLEMENTATION MISSING : %s]\n", __func__)

size_t strcspn(const char *s1, const char *s2)
{
	int i, j;

	for (i = 0; i < strlen(s2); ++i) {
		for (j = 0; j < strlen(s1); ++j) {
			if (s1[j] == s2[i]) {
				return j;
			}
		}
	}

	return strlen(s1);
}

int iscntrl(int c)
{
	/* All the characters placed before the space on the ASCII table
	 * and the 0x7F character (DEL) are control characters.
	 */
	return (int)(c < ' ' || c == 0x7F);
}

struct tm *gmtime(const time_t *ptime)
{
	FN_MISSING();

	return NULL;
}

size_t strftime(char *dst, size_t dst_size,
		const char *fmt,
		const struct tm *tm)
{
	FN_MISSING();

	return 0;
}

double difftime (time_t end, time_t beg)
{
	return end - beg;
}

struct __strerr_wrap {
	int err;
	const char *errstr;
};

/* Implementation suggested by @rakons in #16527 */
#define STRERR_DEFINE(e)	{e, #e}

static const struct __strerr_wrap error_strings[] = {
	STRERR_DEFINE(EILSEQ),
	STRERR_DEFINE(EDOM),
	STRERR_DEFINE(ERANGE),
	STRERR_DEFINE(ENOTTY),
	STRERR_DEFINE(EACCES),
	STRERR_DEFINE(EPERM),
	STRERR_DEFINE(ENOENT),
	STRERR_DEFINE(ESRCH),
	STRERR_DEFINE(EEXIST),
	STRERR_DEFINE(ENOSPC),
	STRERR_DEFINE(ENOMEM),
	STRERR_DEFINE(EBUSY),
	STRERR_DEFINE(EINTR),
	STRERR_DEFINE(EAGAIN),
	STRERR_DEFINE(ESPIPE),
	STRERR_DEFINE(EXDEV),
	STRERR_DEFINE(EROFS),
	STRERR_DEFINE(ENOTEMPTY),
	STRERR_DEFINE(ECONNRESET),
	STRERR_DEFINE(ETIMEDOUT),
	STRERR_DEFINE(ECONNREFUSED),
	STRERR_DEFINE(EHOSTDOWN),
	STRERR_DEFINE(EHOSTUNREACH),
	STRERR_DEFINE(EADDRINUSE),
	STRERR_DEFINE(EPIPE),
	STRERR_DEFINE(EIO),
	STRERR_DEFINE(ENXIO),
	STRERR_DEFINE(ENOTBLK),
	STRERR_DEFINE(ENODEV),
	STRERR_DEFINE(ENOTDIR),
	STRERR_DEFINE(EISDIR),
	STRERR_DEFINE(ETXTBSY),
	STRERR_DEFINE(ENOEXEC),
	STRERR_DEFINE(EINVAL),
	STRERR_DEFINE(E2BIG),
	STRERR_DEFINE(ELOOP),
	STRERR_DEFINE(ENAMETOOLONG),
	STRERR_DEFINE(ENFILE),
	STRERR_DEFINE(EMFILE),
	STRERR_DEFINE(EBADF),
	STRERR_DEFINE(ECHILD),
	STRERR_DEFINE(EFAULT),
	STRERR_DEFINE(EFBIG),
	STRERR_DEFINE(EMLINK),
	STRERR_DEFINE(ENOLCK),
	STRERR_DEFINE(EDEADLK),
	STRERR_DEFINE(ECANCELED),
	STRERR_DEFINE(ENOSYS),
	STRERR_DEFINE(ENOMSG),
	STRERR_DEFINE(ENOSTR),
	STRERR_DEFINE(ENODATA),
	STRERR_DEFINE(ETIME),
	STRERR_DEFINE(ENOSR),
	STRERR_DEFINE(EPROTO),
	STRERR_DEFINE(EBADMSG),
	STRERR_DEFINE(ENOTSOCK),
	STRERR_DEFINE(EDESTADDRREQ),
	STRERR_DEFINE(EMSGSIZE),
	STRERR_DEFINE(EPROTOTYPE),
	STRERR_DEFINE(ENOPROTOOPT),
	STRERR_DEFINE(EPROTONOSUPPORT),
	STRERR_DEFINE(ESOCKTNOSUPPORT),
	STRERR_DEFINE(ENOTSUP),
	STRERR_DEFINE(EPFNOSUPPORT),
	STRERR_DEFINE(EAFNOSUPPORT),
	STRERR_DEFINE(EADDRNOTAVAIL),
	STRERR_DEFINE(ENETDOWN),
	STRERR_DEFINE(ENETUNREACH),
	STRERR_DEFINE(ENETRESET),
	STRERR_DEFINE(ECONNABORTED),
	STRERR_DEFINE(ENOBUFS),
	STRERR_DEFINE(EISCONN),
	STRERR_DEFINE(ENOTCONN),
	STRERR_DEFINE(ESHUTDOWN),
	STRERR_DEFINE(EALREADY),
	STRERR_DEFINE(EINPROGRESS),
};

static char* strerr_unknown = "UNKNOWN";

char *strerror(int err)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(error_strings); ++i) {
		if (error_strings[i].err == err) {
			return (char *)error_strings[i].errstr;
		}
	}

	return strerr_unknown;
}

int sscanf(const char * s, const char * format, ...)
{
	FN_MISSING();

	return 0;
}

double atof(const char* str)
{
	/* XXX good enough for civetweb uses */
	return (double)atoi(str);
}

long long int strtoll(const char* str, char** endptr, int base)
{
	/* XXX good enough for civetweb uses */
	return (long long int)strtol(str, endptr, base);
}

time_t time(time_t *t)
{
	return 0;
}
