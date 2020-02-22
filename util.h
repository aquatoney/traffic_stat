
#include "stdlib.h"

#define likely(x) __glibc_likely(x)
#define unlikely(x) __glibc_unlikely(x)

void exit_error_usage();
void exit_print_usage();

#define LIVE_CAP 1
#define OFFLINE_CAP 2
#define WRITE_CAP 4

struct stat_parameters {
	int setting;
	char device[1024];
	char read_file[1024];
	char write_file[1024];
	unsigned long long max_cap;
};


