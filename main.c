#include "util.h"
#include "stat.h"

#include "signal.h"
#include "string.h"
#include "stdio.h"
#include <pcap.h>


pcap_t* desc;
pcap_dumper_t* dump_file;
struct statistic stat;
struct stat_parameters paras;
unsigned long long cur_pkt_num;


void close_stat()
{
    if (WRITE_CAP & paras.setting) {
    	pcap_dump_close(dump_file);
    } 
}

void stat_handler(unsigned char* par, struct pcap_pkthdr* hdr, unsigned char* data)
{
	if (paras.max_cap != 0 && ++cur_pkt_num >= paras.max_cap) {
		pcap_breakloop(desc);
	}

	base_stat(&stat, data, hdr->len);
	ip_stat(&stat, data, hdr->len);
	tcp_stat(&stat, data, hdr->len);

	if (WRITE_CAP & paras.setting) {
		pcap_dump((unsigned char *)dump_file, hdr, data);
	}
}


void ctrl_c_handler(int sig)
{
    printf("\nwill shut down (ctrl-c again to kill)\n");
    pcap_breakloop(desc);
}


void init_stat()
{
	char errbuf[1024];
	desc = NULL;
	dump_file = NULL;
	cur_pkt_num = 0;
	memset(&stat, 0, sizeof(struct statistic));

	if (LIVE_CAP & paras.setting && OFFLINE_CAP & paras.setting) {
		printf("Cannot use -r and -i together\n");
	}

	if (LIVE_CAP & paras.setting) {
		desc = pcap_open_live(paras.device, 16384, 1, -1, errbuf);
		if (desc == NULL) {
			printf("Invalid device: %s\n", paras.device);
			exit(0);
		}
	}
	if (OFFLINE_CAP & paras.setting) {
		desc = pcap_open_offline(paras.read_file, errbuf);
		if (desc == NULL) {
			printf("Invalid read filename: %s\n", paras.read_file);
			exit(0);
		}
	}

	if (WRITE_CAP & paras.setting) {
		dump_file = pcap_dump_open(desc, paras.write_file);
		if (dump_file == NULL) {
			printf("Invalid write filename: %s\n", paras.write_file);
			exit(0);
		}
	}
}


int main(int argc, char const *argv[])
{	
	signal(SIGINT, ctrl_c_handler);
	memset(&paras, 0, sizeof(struct stat_parameters));


	int i = 1;
	while (i < argc) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			exit_print_usage();
		}
		else if (strcmp(argv[i], "-i") == 0) {
			paras.setting |= LIVE_CAP;
			strcpy(paras.device, argv[i+1]);
			i += 2;
			continue;
		}
		else if (strcmp(argv[i], "-r") == 0) {
			paras.setting |= OFFLINE_CAP;
			strcpy(paras.read_file, argv[i+1]);
			i += 2;
			continue;
		}
		else if (strcmp(argv[i], "-w") == 0) {
			paras.setting |= WRITE_CAP;
			strcpy(paras.write_file, argv[i+1]);
			i += 2;
			continue;
		}
		else if (strcmp(argv[i], "-c") == 0) {
			paras.max_cap = atoi(argv[i+1]);
			i += 2;
			continue;
		}
		else {
			exit_error_usage();
		}
	}

	init_stat();

	pcap_loop(desc, -1, (pcap_handler) stat_handler, NULL);

	close_stat();

	summary(&stat);

	return 0;
}