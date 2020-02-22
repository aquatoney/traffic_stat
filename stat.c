#include "stat.h"
#include "util.h"

#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>


int is_ip_pkt(unsigned char* data, unsigned data_len)
{	
	if (data_len < MIN_IP_PKT_LEN) return -1;
	return (data[12] == 0x08 && data[13] == 0x00);
}

int is_tcp_pkt(unsigned char* data, unsigned data_len)
{	
	if (!is_ip_pkt(data, data_len)) return 0;
	if (data_len < MIN_TCP_PKT_LEN) return -1;

	struct iphdr* ip_hdr = (struct iphdr*)(data+14);
	return (ip_hdr->protocol == 6);
}

int is_udp_pkt(unsigned char* data, unsigned data_len)
{
	if (!is_ip_pkt(data, data_len)) return 0;
	if (data_len < MIN_UDP_PKT_LEN) return -1;

	struct iphdr* ip_hdr = (struct iphdr*)(data+14);
	return (ip_hdr->protocol == 17);
}

void base_stat(struct statistic* stat, unsigned char* data, unsigned data_len)
{
	stat->pkt_num++;
	stat->pkt_amount += data_len;
}

#define HashAdd(Stat, ObjAdd, ObjTable, KeyName, KeyStruct) \
	HASH_ADD(hh, Stat->ObjTable, KeyName, sizeof(KeyStruct), ObjAdd);

#define HashFind(Stat, ObjTable, FindKey, KeyStruct, ObjStruct) \
	struct ObjStruct* found_##ObjStruct; \
	HASH_FIND(hh, Stat->ObjTable, FindKey, sizeof(KeyStruct), found_##ObjStruct);


struct unique_ip_tuple find_ip_tuple;

void ip_stat(struct statistic* stat, unsigned char* data, unsigned data_len)
{
	if (unlikely(!is_ip_pkt(data, data_len))) {
		stat->non_ip_pkt_num++;
		stat->non_ip_pkt_amount += data_len;
		return;
	}

	stat->ip_pkt_num++;
	stat->ip_pkt_amount += data_len;

	struct iphdr* ip_hdr = (struct iphdr*)(data+14);
	find_ip_tuple.tuple2.saddr = ip_hdr->saddr;
	find_ip_tuple.tuple2.daddr = ip_hdr->daddr;
	HashFind(stat, unique_ip_tuples, &find_ip_tuple.tuple2, tuple2_key_t, unique_ip_tuple);
	if (found_unique_ip_tuple == NULL) {
		stat->unique_ip_tuple_num++;

		struct unique_ip_tuple* self = (struct unique_ip_tuple*)malloc(sizeof(struct unique_ip_tuple));
		struct unique_ip_tuple* pair = (struct unique_ip_tuple*)malloc(sizeof(struct unique_ip_tuple));
		self->pair = pair;
		pair->pair = self;
		memcpy(&self->tuple2, &find_ip_tuple.tuple2, sizeof(tuple2_key_t));
		self->pkt_num ++;
		self->amount += data_len;
		HashAdd(stat, self, unique_ip_tuples, tuple2, tuple2_key_t);	

		find_ip_tuple.tuple2.saddr = ip_hdr->daddr;
		find_ip_tuple.tuple2.daddr = ip_hdr->saddr;
		memcpy(&pair->tuple2, &find_ip_tuple.tuple2, sizeof(tuple2_key_t));
		HashAdd(stat, pair, unique_ip_tuples, tuple2, tuple2_key_t);	
	}
	else {
		found_unique_ip_tuple->pkt_num ++;
		found_unique_ip_tuple->amount += data_len;
	}
}

tuple4_key_t find_tuple4;
struct unique_tcp_tuple find_tcp_tuple;

void tcp_stat(struct statistic* stat, unsigned char* data, unsigned data_len)
{
	if (unlikely(!is_tcp_pkt(data, data_len))) return;

	stat->tcp_pkt_num++;
	stat->tcp_pkt_amount += data_len;

	struct iphdr* ip_hdr = (struct iphdr*)(data+14);
	struct tcphdr* tcp_hdr = (struct tcphdr*)(data+14+4*ip_hdr->ihl);

	find_tuple4.saddr = ip_hdr->saddr;
	find_tuple4.daddr = ip_hdr->daddr;
	find_tuple4.sport = tcp_hdr->source;
	find_tuple4.dport = tcp_hdr->dest;
	memcpy(&find_tcp_tuple.tuple4, &find_tuple4, sizeof(tuple4_key_t));

	/* TCP Tuple Stat */
	HashFind(stat, unique_tcp_tuples, &find_tcp_tuple.tuple4, tuple4_key_t, unique_tcp_tuple);
	if (found_unique_tcp_tuple == NULL) {
		stat->unique_tcp_tuple_num++;

		struct unique_tcp_tuple* self = (struct unique_tcp_tuple*)malloc(sizeof(struct unique_tcp_tuple));
		struct unique_tcp_tuple* pair = (struct unique_tcp_tuple*)malloc(sizeof(struct unique_tcp_tuple));
		memset(self, 0, sizeof(struct unique_tcp_tuple));
		memset(pair, 0, sizeof(struct unique_tcp_tuple));
		if (tcp_hdr->syn) {
			self->has_syn = 1;
			pair->has_syn = 1;
		}
		self->pair = pair;
		pair->pair = self;
		memcpy(&self->tuple4, &find_tcp_tuple.tuple4, sizeof(tuple4_key_t));
		self->pkt_num ++;
		self->amount += data_len;
		HashAdd(stat, self, unique_tcp_tuples, tuple4, tuple4_key_t);	

		find_tcp_tuple.tuple4.saddr = ip_hdr->daddr;
		find_tcp_tuple.tuple4.daddr = ip_hdr->saddr;
		find_tcp_tuple.tuple4.sport = tcp_hdr->dest;
		find_tcp_tuple.tuple4.dport = tcp_hdr->source;
		memcpy(&pair->tuple4, &find_tcp_tuple.tuple4, sizeof(tuple4_key_t));
		HashAdd(stat, pair, unique_tcp_tuples, tuple4, tuple4_key_t);	
	}
	else {
		if (tcp_hdr->fin) {
			found_unique_tcp_tuple->has_fin = 1;
			found_unique_tcp_tuple->pair->has_fin = 1;
		}
		found_unique_tcp_tuple->pkt_num ++;
		found_unique_tcp_tuple->amount += data_len;
	}
}

void tcp_summary(struct statistic* stat)
{
	struct unique_tcp_tuple* cursor;

    for(cursor = stat->unique_tcp_tuples; cursor != NULL; cursor = cursor->hh.next) {
    	if (cursor->traversed) continue;
    	cursor->traversed = 1;
    	cursor->pair->traversed = 1;
    	if (cursor->has_syn) {
    		stat->tcp_conn_num++;
    		if (cursor->has_fin) {
    			stat->tcp_complete_conn_num++;
    		}
    	}
    }
}

void udp_stat(struct statistic* stat, unsigned char* data, unsigned data_len)
{

}

void summary(struct statistic* stat)
{
	tcp_summary(stat);

	printf("Base Stat:\n");
	printf("Packets: %llu (%llu bytes)\n", stat->pkt_num, stat->pkt_amount);
	printf("==============\n");
	printf("IP Stat:\n");
	printf("IP Packets: %llu (%llu bytes)\n", stat->ip_pkt_num, stat->ip_pkt_amount);
	printf("IP Tuples: %llu\n", stat->unique_ip_tuple_num);
	printf("Non-IP Packets: %llu (%llu bytes)\n", stat->non_ip_pkt_num, stat->non_ip_pkt_amount);
	printf("==============\n");
	printf("TCP Stat:\n");
	printf("TCP Packets: %llu (%llu bytes)\n", stat->tcp_pkt_num, stat->tcp_pkt_amount);
	printf("TCP Connections (unique tuples): %llu\n", stat->unique_tcp_tuple_num);
	printf("TCP Connections (with SYN): %llu\n", stat->tcp_conn_num);
	printf("TCP Connections (with SYN and FIN): %llu\n", stat->tcp_complete_conn_num);
}