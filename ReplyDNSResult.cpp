#include "ReplyDNSResult.h"

using namespace std;

extern host_item *hosts_list[];
extern int host_counter;

WEBADDR_TYPE getWebAddrType(char *addr)
{
	for(int i = 0; i < host_counter; i++)
		if(strcmp(addr, hosts_list[i]->webaddr) == 0)
			return hosts_list[i]->type;
	return ADDR_NOT_FOUND;
}

DNSPacket *getDNSResult(DNSPacket *ori_packet)
{
	DNSPacket *ret_packet = new DNSPacket;
	DNSHeader *ret_header = new DNSHeader;
	DNSQuery *ret_query = ori_packet->p_qpointer;
	DNSResponse *ret_response = new DNSResponse;
	u_short ret_id;

	WEBADDR_TYPE addr_type = getWebAddrType(ori_packet->p_qpointer->q_qname);

	// Forward any request not of type 1
	if(ori_packet->p_qpointer->q_qtype != 1)
		addr_type = ADDR_NOT_FOUND;

	switch ((int)addr_type)
	{
	case ADDR_BLOCKED:
		{
			//Construct new DNSResponse
			ret_response->r_name = ori_packet->p_qpointer->q_qname;
			ret_response->r_type = 1;
			ret_response->r_class = ori_packet->p_qpointer->q_qclass;
			ret_response->r_ttl = 0x100;
			ret_response->r_rdlength = 4;
			char *blocked_addr = "\0\0\0\0";							// Blocked IP Addr: 0.0.0.0
			ret_response->r_rdata = blocked_addr;

			//Construct new DNSHeader
			ret_header->h_id = ori_packet->p_header->h_id;
			ret_header->h_qr = 1;
			ret_header->h_opcode = ori_packet->p_header->h_opcode;
			ret_header->h_aa = 0;
			ret_header->h_tc = 0;
			ret_header->h_rd = 1;
			ret_header->h_z = 0;
			ret_header->h_rcode = 0;
			ret_header->h_qdcount = 1;
			ret_header->h_ancount = 1;
			ret_header->h_nscount = 0;
			ret_header->h_arcount = 0;
		}
		break;
	case ADDR_CACHED:
		{
			//Construct new DNSResponse
			ret_response->r_name = ori_packet->p_qpointer->q_qname;
			ret_response->r_type = 1;
			ret_response->r_class = ori_packet->p_qpointer->q_qclass;
			ret_response->r_ttl = 0x100;
			ret_response->r_rdlength = 4;
			char *blocked_addr = "\0\0\0\0";							// Blocked IP Addr: 0.0.0.0
			ret_response->r_rdata = blocked_addr;

			//Construct new DNSHeader
			ret_header->h_id = ori_packet->p_header->h_id;
			ret_header->h_qr = 1;
			ret_header->h_opcode = ori_packet->p_header->h_opcode;
			ret_header->h_aa = 0;
			ret_header->h_tc = 0;
			ret_header->h_rd = 1;
			ret_header->h_z = 0;
			ret_header->h_rcode = 0;
			ret_header->h_qdcount = 1;
			ret_header->h_ancount = 1;
			ret_header->h_nscount = 0;
			ret_header->h_arcount = 0;
		}
		break;
	case ADDR_NOT_FOUND:
		{
			//iResult = sendto(send_socket, recvbuf, recvbuflen, 0, (struct sockaddr*)&servaddr,sizeof(servaddr));
			//if(iResult == SOCKET_ERROR)
			//	printf("sendto() failed with error code : %d" , WSAGetLastError());

			//iResult = recv(send_socket, recvbuf, recvbuflen, 0);
			//if(iResult == SOCKET_ERROR)
			//	printf("recv() failed with error code : %d" , WSAGetLastError());
			//else
			//	printf("Bytes received from 10.3.9.4: %d\n", iResult);

			int new_id = assignNewID(ori_packet->p_header->h_id);
			ori_packet->p_header->h_id  = new_id;
			
		}
		break;
	}

	// Form new header
	ret_packet->p_header = ret_header;
	ret_packet->p_qpointer = ret_query;
	ret_packet->p_rpointer = ret_response;

	return NULL;
}

