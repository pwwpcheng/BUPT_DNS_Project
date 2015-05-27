#include "ReplyDNSResult.h"

using namespace std;

extern host_item *hosts_list[];
extern cached_item *cached_list[];
extern int host_counter;
extern int cached_counter;
extern SOCKET send_socket;
std::mutex cache_mutex;

/* 
 * GetWebAddrType tells if the searched address is in host list
 * returns WEBADDR_TYPE (ADDR_CACHED, ADDR_BLOCKED, ADDR_NOT_FOUND)
 * returns real ip if found, 0.0.0.0 if not found.
 */

WEBADDR_TYPE getWebAddrType(char *addr, UINT32 *ip)
{
	int i;
	*ip = 0x0;
	string s(addr);

	// Substitude unreadable . to '.' for further comparison
	for(i = 0; i < s.length(); i++)
	{
		if(s[i] < 0x20)		
			s[i] = '.';
	}

	// Compare request address with host
	// Return cached/blocked ip if found
	for(i = 0; i < host_counter; i++)
	{
		if(s.find(hosts_list[i]->webaddr, 0) != s.npos  && s.length() == strlen(hosts_list[i]->webaddr) + 1)
		{
			*ip = hosts_list[i]->ip_addr;
			if(*ip != 0)
				return ADDR_CACHED;
			else
				return ADDR_BLOCKED;
		}
	}

	cache_mutex.lock();
	for(i = 0; i < MAX_CACHED_ITEM; i++)
	{
		if(!cached_list[i]->occupied) continue;
		if(strcmp(addr, cached_list[i]->webaddr ) == 0)
		{
			*ip = cached_list[i]->ip_addr;
			cached_list[i]->ttl = 600;
			std::cout << "[CACHEHIT]: Cache ID: " << i << std::endl;
			cache_mutex.unlock();
			return ADDR_CACHED;
		}
	}
	cache_mutex.unlock();
	return ADDR_NOT_FOUND;
}

/*
 * GetDNSResult reads in a DNS Query package that contains cached webaddress in host file
 * returns a legal response package
 * In:  DNSPacket ori_packet - Original Request
 *	    UINT32 ip_addr - ip for cached address in host file
 * Out: DNSPacket ret_packet - Legal response package with DNSPacket format
 */

DNSPacket *getDNSResult(DNSPacket *ori_packet, UINT32 ip_addr, WEBADDR_TYPE addr_type)
{
	DNSPacket *ret_packet = new DNSPacket;
	DNSHeader *ret_header = new DNSHeader;
	DNSQuery *ret_query = ori_packet->p_qpointer[0];
	DNSResponse *ret_response = new DNSResponse;
	u_short ret_id;

	if(addr_type == ADDR_BLOCKED)
	{
		//Construct new DNSHeader
		ret_header->h_id = ori_packet->p_header->h_id;
		ret_header->h_qr = 1;
		ret_header->h_opcode = ori_packet->p_header->h_opcode;
		ret_header->h_aa = 0;
		ret_header->h_tc = 0;
		ret_header->h_rd = 1;
		ret_header->h_ra = 1;
		ret_header->h_rcode = 3;
		ret_header->h_qdcount = 0;
		ret_header->h_ancount = 0;
		ret_header->h_nscount = 0;
		ret_header->h_arcount = 0;
	
		// Form new packet
		ret_packet->p_header = ret_header;
		ret_packet->p_qpointer[0] = NULL;
		ret_packet->p_rpointer[0] = NULL;
		ret_packet->p_qr = Q_RESPONSE;
	}
	else
	{
		//Construct new DNSResponse
		ret_response->r_name = ori_packet->p_qpointer[0]->q_qname;
		ret_response->r_type = 1;
		ret_response->r_class = ori_packet->p_qpointer[0]->q_qclass;
		ret_response->r_ttl = 0x100;
		ret_response->r_rdlength = 4;
		ret_response->r_rdata = (char*)malloc(sizeof(UINT32) + 1);
		*(UINT32*)(ret_response->r_rdata) = htonl(ip_addr);

		//Construct new DNSHeader
		ret_header->h_id = ori_packet->p_header->h_id;
		ret_header->h_qr = 1;
		ret_header->h_opcode = ori_packet->p_header->h_opcode;
		ret_header->h_aa = 0;
		ret_header->h_tc = 0;
		ret_header->h_rd = 1;
		ret_header->h_ra = 1;
		ret_header->h_rcode = 0;
		ret_header->h_rcode = 0;
		ret_header->h_qdcount = 1;
		ret_header->h_ancount = 1;
		ret_header->h_nscount = 0;
		ret_header->h_arcount = 0;
	
		// Form new packet
		ret_packet->p_header = ret_header;
		ret_packet->p_qpointer[0] = ret_query;
		ret_packet->p_rpointer[0] = ret_response;
		ret_packet->p_qr = Q_RESPONSE;
	}

	return ret_packet;
}

