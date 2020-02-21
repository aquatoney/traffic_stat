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
	printf("-r [pcap]: capture offline [pcap]\n");
	exit(0);
}