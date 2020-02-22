
#include "uthash.h"

typedef struct {
	unsigned saddr;
	unsigned daddr;
} tuple2_key_t;

struct unique_ip_tuple {
    tuple2_key_t tuple2;
    unsigned long long pkt_num;
    unsigned long long amount;
    struct unique_ip_tuple* pair;
    UT_hash_handle hh;
};

typedef struct {
	unsigned saddr;
	unsigned daddr;
	unsigned short sport;
	unsigned short dport;
} tuple4_key_t;


struct unique_tcp_tuple {
    tuple4_key_t tuple4;
    unsigned long long pkt_num;
    unsigned long long amount;
    struct unique_tcp_tuple* pair;
    int has_syn;
    int has_fin;
    int traversed;
    UT_hash_handle hh;
};

struct unique_udp_tuple {
    tuple4_key_t tuple4;
    unsigned long long pkt_num;
    unsigned long long amount;
    struct unique_udp_tuple* pair;
    UT_hash_handle hh;
};

struct statistic {
	unsigned long long pkt_amount;
	unsigned long long pkt_num;

	unsigned long long non_ip_pkt_num;
	unsigned long long non_ip_pkt_amount;

	unsigned long long ip_pkt_amount;
	unsigned long long ip_pkt_num;
	unsigned long long unique_ip_tuple_num;
	struct unique_ip_tuple* unique_ip_tuples;

	unsigned long long tcp_pkt_amount;
	unsigned long long tcp_pkt_num;
	/* unique 4-tuple in TCP, i.e., not necessarily with handshake*/
	unsigned long long unique_tcp_tuple_num;
	struct unique_tcp_tuple* unique_tcp_tuples;
	/* must handshake using SYN packet */
	unsigned long long tcp_conn_num;
	unsigned long long tcp_complete_conn_num;

	unsigned long long udp_pkt_amount;
	unsigned long long udp_pkt_num;
	unsigned long long unique_udp_tuple_num;
	struct unique_udp_tuple* unique_udp_tuples;

	/* equals to unique_tcp_tuple_num+unique_udp_tuple_num */
	unsigned long long unique_5_tuple_num;
};

#define MIN_IP_PKT_LEN 40
#define MIN_TCP_PKT_LEN 40
#define MIN_UDP_PKT_LEN 40

int is_ip_pkt(unsigned char* data, unsigned data_len);
int is_tcp_pkt(unsigned char* data, unsigned data_len);
int is_udp_pkt(unsigned char* data, unsigned data_len);

void base_stat(struct statistic* stat, unsigned char* data, unsigned data_len);
void ip_stat(struct statistic* stat, unsigned char* data, unsigned data_len);
void tcp_stat(struct statistic* stat, unsigned char* data, unsigned data_len);
void udp_stat(struct statistic* stat, unsigned char* data, unsigned data_len);

void summary(struct statistic* stat);