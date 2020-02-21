#include "util.h"
#include "stat.h"

#include "stdio.h"
#include <pcap.h>


pcap_t* desc;
struct statistic stat;

void stat_handler(unsigned char* par, struct pcap_pkthdr* hdr, unsigned char* data)
{
	base_stat(&stat, data, hdr->len);
	ip_stat(&stat, data, hdr->len);
	tcp_stat(&stat, data, hdr->len);
}



void ctrl_c_handler(int sig)
{
    printf("\nwill shut down (ctrl-c again to kill)\n");
    pcap_breakloop(desc);
}

int main(int argc, char const *argv[])
{	
	desc = NULL;
	char errbuf[1024];
	memset(&stat, 0, sizeof(struct statistic));

	if (argc < 2 || argc > 3) {
		exit_error_usage();
	}

	if (argc == 2) {
		if (strcmp(argv[1], "-h") && strcmp(argv[1], "--help")) {
			exit_error_usage();
		}
		exit_print_usage();
	}

	if (argc == 3) {
		if (strcmp(argv[1], "-i") == 0) {
			desc = pcap_open_live(argv[2], 16384, 1, -1, errbuf);
		}
		if (strcmp(argv[1], "-r") == 0) {
			desc = pcap_open_offline(argv[2], errbuf);
		}
		if (desc == NULL) {
			printf("Invalid device or filename: %s\n", argv[2]);
			exit(0);
		}
	}

	pcap_loop(desc, -1, (pcap_handler) stat_handler, NULL);

	summary(&stat);

	return 0;
}