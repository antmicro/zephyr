#include <zephyr.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#define F_SETFD 2
#define FD_CLOEXEC 1

size_t strcspn(const char *s1, const char *s2);
size_t strspn(const char *s1, const char *s2);
int iscntrl(int c);

double atof (const char* str);
long long int strtoll (const char* str, char** endptr, int base);
int sscanf(const char * s, const char * format, ...);
char *strerror(int err);
unsigned long long int strtoull(const char* str, char** endptr, int base);

time_t time(time_t *t);
struct tm * gmtime(const time_t *ptime);
size_t strftime(char *dst, size_t dst_size, const char *fmt, const struct tm *tm);
double difftime (time_t end, time_t beg);
struct tm *localtime(const time_t *timer);

int fileno(FILE *stream);
int ferror(FILE *stream);
int fclose(FILE *stream);
int fseeko(FILE *stream, off_t offset, int whence);
FILE *fopen(const char * filename, const char * mode);
char *fgets(char * str, int num, FILE * stream);
size_t fread(void * ptr, size_t size, size_t count, FILE * stream);
int remove(const char *filename);
