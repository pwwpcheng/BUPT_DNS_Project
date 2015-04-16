#ifndef MAINHEADER_H
#define MAINHEADER_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#pragma comment (lib, "Ws2_32.lib")

#define DNS_PORT 53				//DNS serves on port 53
#define DEFAULT_BUFLEN 1024
#define DNS_HEADER_LEN 12
#define MAX_HOST_ITEM 1010
#define UPPER_DNS "10.3.9.4"
#define HOST_FILE_LOC "C:\\dnsrelay.txt"
#define BLOCKED_ADDR_IP "0.0.0.0"

enum Query_QR {Q_QUERY = 0, Q_RESPONSE = 1};
enum WEBADDR_TYPE {ADDR_BLOCKED = 100, ADDR_CACHED, ADDR_NOT_FOUND,};
enum PACKET_TYPE {SELF_CREATED_PACKET, UPPER_DNS_ANSWER};

struct DnsHeader
{
	u_short h_id;
	bool h_qr;
	u_short h_opcode;
	bool h_aa;
	bool h_tc;
	bool h_rd;
	bool h_ra;
	char h_rcode;
	u_short h_qdcount;
	u_short h_ancount;
	u_short h_nscount;
	u_short h_arcount;
};
typedef struct DnsHeader DNSHeader;

struct DnsQuery
{
	char *q_qname;
	u_short q_qtype;
	u_short q_qclass;
};
typedef struct DnsQuery DNSQuery;

struct DnsResponse
{
	char *r_name;
	u_short r_type;
	u_short r_class;
	int r_ttl;
	u_short r_rdlength;
	char* r_rdata;
};
typedef struct DnsResponse DNSResponse;

struct DnsPacket
{
	PACKET_TYPE p_type;
	Query_QR p_qr;
	DNSHeader *p_header;
	DNSQuery *p_qpointer;
	DNSResponse *p_rpointer;
};
typedef struct DnsPacket DNSPacket;

struct host_item_struct
{
	UINT32 ip_addr;
	char* webaddr;
	WEBADDR_TYPE type;
};
typedef struct host_item_struct host_item;

// All functions are defined as below
int startWSA();
int startDNSServer(SOCKET *);
int connectToUpperDNS(SOCKET *);
DNSHeader *fromDNSHeader(char*, char**);
DNSQuery *fromDNSQuery(char*, char**);
DNSResponse *fromDNSResponse(char*, char**);
char *toDNSHeader(DNSHeader*);
char *toDNSQuery(DNSQuery*);
char *toDNSResponse(DNSResponse*);
void loadHosts();
u_short assignNewID(u_short);
u_short getOriginalID(u_short);
DNSPacket *unpackDNSPacket(char *);
char *packDNSPacket(DNSPacket *, int *);



#endif