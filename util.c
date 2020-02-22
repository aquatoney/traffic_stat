#include "util.h"
#include "stdio.h"

void exit_error_usage()
{
	printf("Unknown arguments. Use -h or --help for usage\n");
	exit(0);
}

void exit_print_usage()
{
	printf("-h: this message\n");
	printf("-i [dev]: capture live traffic from [dev]\n");
	printf("-r [read]: capture offline file [read]\n");
	printf("-w [write]: write the capture to file [write]\n");
	printf("-c [max_cap]: process the first [max_cap] packets\n");
	exit(0);
}