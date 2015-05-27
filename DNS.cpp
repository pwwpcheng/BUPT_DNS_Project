#include "MainHeader.h"
#include "ReplyDNSResult.h"

#define THREADDEBUG std::cout << "[Thread " << t_id << "]: "

const int SIP_UDP_CONNRESET = -1744830452;
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR,12)
#define TOPORT(i) i + 15000

host_item *hosts_list[MAX_HOST_ITEM];
cached_item *cached_list[MAX_HOST_ITEM];
ReqPool *request_pool = new ReqPool[MAX_REQ];
std::mutex id_mutex, pool_mutex, req_counter_mutex;
extern std::mutex cache_mutex;
int req_counter = 0, host_counter = 0, cached_counter = 0;
 
int main()
{
	// Initialize, load history data
	int iResult = 0;
	int thread_num = 0;

	iResult = startWSA(); 
	loadHosts();            // 是什么host?
	
	// Initialize, create listen socket
	SOCKET listen_socket;
	iResult = startDNSServer(&listen_socket);					
	if (iResult == 1) return 255;  // 255 是什么错？

	// Initialize Cache
	for(int i = 0; i < MAX_CACHED_ITEM; i++)
	{	
		cached_list[i] = new cached_item;
		cached_list[i]->occupied = false;
		cached_list[i]->ttl = 0;
		cached_list[i]->webaddr = new char[256];
	}

	// Initialize DNSRequest Pool
	for(int i = 0; i < MAX_REQ; i++)
	{
		request_pool[i].available = true;
	}

	std::thread dns_consulting_threads1(DNSHandleThread, "10.3.9.4", listen_socket, 1);
	std::thread dns_consulting_threads2(DNSHandleThread, "101.226.4.6", listen_socket, 2);
	std::thread dns_consulting_threads3(DNSHandleThread, "10.3.9.5", listen_socket, 3);
	std::thread dns_consulting_threads4(DNSHandleThread, "10.3.9.6", listen_socket, 4);
	std::thread cache_thread(flushDnsCacheThread);
	std::thread pool_flush_thread(flushDNSRequestThread);

	std::cout << "Initialize Complete. " << std::endl;

	do
	{
		char *ret_ptr = NULL, *recvbuf = NULL;
		int recvbuflen = DEFAULT_BUFLEN, sendbuflen = DEFAULT_BUFLEN;
		recvbuf = (char*)malloc(recvbuflen * sizeof(char));

		struct sockaddr_in clientaddr;
		int client_addr_len = sizeof(clientaddr);
		memset(recvbuf, '\0', sizeof(recvbuf));
		ZeroMemory(&clientaddr, sizeof(clientaddr));

		DWORD dwBytesReturned = 0;
		BOOL bNewBehavior = FALSE;
		DWORD status;

		 //disable  new behavior using
		 //IOCTL: SIO_UDP_CONNRESET
		status = WSAIoctl(listen_socket, SIO_UDP_CONNRESET,
			&bNewBehavior, sizeof(bNewBehavior),
			NULL, 0, &dwBytesReturned,
			NULL, NULL);

		if (SOCKET_ERROR == status)
		{
			DWORD dwErr = WSAGetLastError();
			if (WSAEWOULDBLOCK == dwErr)
			{
				// nothing to do
				return 255;
			}
			else
			{
				//cout << "WSAIoctl(SIO_UDP_CONNRESET) Error: " << dwErr << endl;
				return 255;
			}
		}

		// Receive DNS Requests
		iResult = recvfrom(listen_socket, recvbuf, recvbuflen, 0, (struct sockaddr*)&clientaddr, &client_addr_len);
		if (iResult == SOCKET_ERROR) {
			printf("[MainProc]: recvfrom_client() error with code: %d\n", WSAGetLastError());
			break;
		}
		else{
			printf("[MainProc]: Bytes received: %d\n", iResult);
			DNSRequest *new_req = new DNSRequest;
			new_req->client_addr = clientaddr;
			new_req->client_addr_len = client_addr_len;
			new_req->packet = unpackDNSPacket(recvbuf);
			new_req->served = false;
			new_req->ttl = 600;
			iResult = addDNSRequestPool(new_req);
			if(iResult == MAX_REQ + 1)
				std::cout << "[MainProc]: Too many requests. Ignore current one.";
		}

	}while(iResult >= 0);

	int s;
	std::cin >> s;
	return 0;
}

/*Initalize WinSocket*/
int startWSA()
{
	int iResult = 0;

	// Initalize Winsock
	WSADATA wsaData;
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
		return 255;
    }
	//cout << "WinSock Initialized." << endl;
	return 0;
}

/*
 * Read in a header pointer, return a full structure of DNS header
 * Header length: 12 bytes
 * Source pointer won't changed
 */
DNSHeader* fromDNSHeader(char* src, char **ret_ptr)
{
	DNSHeader *new_q;
	new_q = new DNSHeader;

	int loc_pointer = 0;
	u_short *pointer = (u_short*)src;
	u_short cur_word = htons(*pointer);

	//Get transaction ID
	new_q->h_id = (int)cur_word;
	
	//Get flags
	cur_word = htons(*(++pointer));
	new_q->h_qr		= (bool)	((cur_word & 0x8000) >> 15);
	new_q->h_opcode = (u_short)	((cur_word & 0x7800) >> 11);
	new_q->h_aa		= (bool)	((cur_word & 0x0400) >> 10);
	new_q->h_tc		= (bool)	((cur_word & 0x0200) >> 9);
	new_q->h_rd		= (bool)	((cur_word & 0x0100) >> 8);
	new_q->h_ra		= (bool)	((cur_word & 0x0080) >> 7);
	new_q->h_rcode	= (u_short)	((cur_word & 0x000F));

	//Get Counts
	cur_word = htons(*(++pointer));
	new_q->h_qdcount = cur_word;
	cur_word = htons(*(++pointer));
	new_q->h_ancount = cur_word;
	cur_word = htons(*(++pointer));
	new_q->h_nscount = cur_word;
	cur_word = htons(*(++pointer));
	new_q->h_arcount = cur_word;

	*ret_ptr = (char*)(++pointer);
	return new_q;
}

DNSQuery *fromDNSQuery(char *src, char **ret_ptr)
{
	int qname_length = 0;
	DNSQuery *new_q = new DNSQuery;

	do
		qname_length++;							//Get QueryName length
	while(*(src + qname_length) != '\0');
	char *s = (char*)malloc(qname_length * sizeof(char));
	strcpy(s, src);
	new_q->q_qname = s;

	src += (++qname_length);
	u_short *tmp = (u_short*)src;
	new_q->q_qtype = htons(*(tmp++));
	new_q->q_qclass = htons(*tmp);

	*ret_ptr = (char*)(++tmp);
	return new_q;
}

DNSResponse *fromDNSResponse(char* src, char* head, char **ret_ptr)
{
	DNSResponse *new_r = new DNSResponse;
	char *s = (char*)malloc(256 * sizeof(char));
	int qname_length = 0;
	char *final_name_dst = src;
	bool name_jumped = false;

	char *name_pointer = src;
	while(1)
	{
		if(*name_pointer == '\0')
		{
			s[qname_length] = '\0';
			if(name_jumped == false)
				final_name_dst = src + qname_length;
			break;
		}
		if(((*name_pointer) & 0xc0) == 0xc0)
		{
			int new_dst = htons(*((u_short*)name_pointer)) & 0x3f;
			new_dst += (int)head;
			name_jumped = true;
			final_name_dst = name_pointer + 2;
			name_pointer = (char*)new_dst;
			continue;
		}
		if(*name_pointer < 20)
		{
			int tmp_len = *name_pointer++;
			s[qname_length++] = tmp_len;
			for(int i = 0; i < tmp_len; i++)
				s[qname_length++] = *(name_pointer++);
		}
	}

	//do
	//	qname_length++;							//Get QueryName length
	//while(*(src + qname_length) != '\0');
		
	new_r->r_name = s;
	
	src = final_name_dst;
	u_short *tmp = (u_short*)src;
	new_r->r_type = htons(*(tmp++));
	new_r->r_class = htons(*(tmp++));
	new_r->r_ttl = htonl(*((int*)tmp));
	tmp += 2;
	new_r->r_rdlength = htons(*(tmp++));

	src = (char*)tmp;
	s = (char*)malloc((new_r->r_rdlength + 1) * sizeof(char));
	memcpy(s, src, new_r->r_rdlength);
	s[new_r->r_rdlength] = '\0';
	new_r->r_rdata = s;

	*ret_ptr = src + new_r->r_rdlength;
	return new_r;
}

char *toDNSHeader(DNSHeader *ret_h)
{
	u_short *tmp_s;
	char* ret_s;
	tmp_s = (u_short*)malloc(13 * sizeof(char));
	ret_s = (char*)tmp_s;
	*(tmp_s++) = ntohs((u_short)ret_h->h_id);

	*tmp_s = 0;
	u_short tags = 0;
	tags |= (ret_h->h_qr		<< 15);
	tags |= (ret_h->h_opcode	<< 11);
	tags |= (ret_h->h_aa		<< 10);
	tags |= (ret_h->h_tc		<< 9);
	tags |= (ret_h->h_rd		<< 8);
	tags |= (ret_h->h_ra		<< 7);
	tags |= (ret_h->h_rcode);
	*(tmp_s++) = ntohs(tags);
	*(tmp_s++) = ntohs(ret_h->h_qdcount);
	*(tmp_s++) = ntohs(ret_h->h_ancount);
	*(tmp_s++) = ntohs(ret_h->h_nscount);
	*(tmp_s++) = ntohs(ret_h->h_arcount);

	*(char*)tmp_s = '\0';
	return ret_s;
}

/*
 * This function convert DNSQuery struct to binary network stream.
 * Return string's length is not fixed. String ends with '\0'.
 * Ret_r points to the start of return string.
 * Tmp_char_pointer and tmp_u_short_pointer point at the same location whenever needed
 * thus, the program could treat these two pointer as the same pointer, but with different types.
 */
char *toDNSQuery(DNSQuery *ret_q)
{
	char *ret_s, *tmp_char_pointer;
	u_short *tmp_u_short_pointer;
	int tot_query_length;

	tot_query_length = strlen(ret_q->q_qname) + 6;
	ret_s = (char*) malloc (tot_query_length * sizeof(char));
	tmp_char_pointer =  ret_s;

	//Copy qname to reply message
	strcpy(tmp_char_pointer, ret_q->q_qname);
	tmp_char_pointer += strlen(ret_q->q_qname);
	*tmp_char_pointer = '\0';
	tmp_char_pointer++;
	tmp_u_short_pointer = (u_short*)tmp_char_pointer;

	*(tmp_u_short_pointer++) = ntohs(ret_q->q_qtype);
	*(tmp_u_short_pointer++) = ntohs(ret_q->q_qclass);

	tmp_char_pointer = (char*)tmp_u_short_pointer;
	tmp_char_pointer = '\0';
	return ret_s;
}

/*
 * This function converts DNSResponse struct to binary network stream.
 * Usage of ret_s, tmp_char_pointer and tmp_u_short_pointer is the same as char *toDNSQuery(DNSQuery*)
 */

char *toDNSResponse(DNSResponse *ret_r)
{
	char *ret_s, *tmp_char_pointer;
	u_short *tmp_u_short_pointer;
	int tot_response_length;

	//tot_response length = length of r_name + 1(length of '\0') + 2(length of TYPE) + 2(length of CLASS) + 4(length of TTL)
	//						+ 2(length of RDLENGTH) + length of rd + 1(length of '\0' at the end)
	tot_response_length = strlen(ret_r->r_name) + 11 + ret_r->r_rdlength + 1;

	ret_s = (char*) malloc (tot_response_length * sizeof(char));
	tmp_char_pointer = ret_s;
	strcpy(tmp_char_pointer, ret_r->r_name);
	tmp_char_pointer += strlen(ret_r->r_name);
	*tmp_char_pointer = '\0';
	tmp_char_pointer++;
	tmp_u_short_pointer = (u_short*)tmp_char_pointer;

	*tmp_u_short_pointer++ = ntohs(ret_r->r_type);
	*tmp_u_short_pointer++ = ntohs(ret_r->r_class);
	*(int*)tmp_u_short_pointer = ntohl(ret_r->r_ttl);
	tmp_u_short_pointer += 2;
	*tmp_u_short_pointer++ = ntohs(ret_r->r_rdlength);

	tmp_char_pointer = (char*)tmp_u_short_pointer;
	memcpy(tmp_char_pointer, ret_r->r_rdata, ret_r->r_rdlength);

	return ret_s;
}

/*
 * Initialize DNS server.
 * Binding socket on port 53, start listening to requests
 * Pass successfully binded socket to ret_socket.
 * return 0 if succeeded, 1 if failed.
 */

int startDNSServer(SOCKET *ret_socket)
{
	int iResult = 0;
	SOCKET ListenSocket = INVALID_SOCKET;

	//Create a new socket
	ListenSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if(ListenSocket == INVALID_SOCKET)
	{
		std::cout << "Socket creation failed with error: " << iResult << std::endl;
		WSACleanup();
		return 1;
	}
	//cout << "Socket created." << endl;

	struct sockaddr_in hints;
	hints.sin_family = AF_INET;
	hints.sin_addr.s_addr = INADDR_ANY;
	hints.sin_port = htons(DNS_PORT);

	iResult = ::bind(ListenSocket, (struct sockaddr*)&hints, sizeof(hints));
	if (iResult == SOCKET_ERROR) {
		//cout << "Binding failed with error: " <<  iResult << endl;
		WSACleanup();
		return 1;
	}
	//cout << "Binding succeed." << endl;

	*ret_socket = ListenSocket;
	return 0;
}

int bindSocket(SOCKET *ret_socket, struct sockaddr_in* servaddr)
{
	int iResult = 0;
	SOCKET ListenSocket = INVALID_SOCKET;

	//Create a new socket
	ListenSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if(ListenSocket == INVALID_SOCKET)
	{
		std::cout << "Socket creation failed with error: " << iResult << std::endl;
		WSACleanup();
		return 1;
	}
	//cout << "Socket created." << endl;

	iResult = ::bind(ListenSocket, (struct sockaddr*)servaddr, sizeof(*servaddr));
	if (iResult == SOCKET_ERROR) {
		std::cout << " !! Binding failed with error: " <<  iResult << std::endl;
		WSACleanup();
		return 1;
	}
	//cout << "Binding succeed." << endl;

	*ret_socket = ListenSocket;
	return 0;
}

int createUpperDNSSocket(SOCKET *ret_socket)
{
	int iResult;
	SOCKET send_socket = INVALID_SOCKET;
	const unsigned long ul = 1;

	//Create a new socket
	send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(send_socket == INVALID_SOCKET)
	{
		//cout << "Socket creation failed with error: " << iResult << endl;
		WSACleanup();
		return 1;
	}
	//cout << "Socket created." << endl;

	////Set socket mode: unblocked
	//iResult = ioctlsocket(send_socket,FIONBIO,(unsigned long *)&ul);			
	//if(iResult == SOCKET_ERROR)
	//{
	//	//cout << "Socket mode changing failed. ERROR " << iResult << endl;
	//	WSACleanup();
	//	return 1;
	//}

	//Return created socket
	*ret_socket = send_socket;
	return 0;
}

/*
 * This function loads host file in HOST_FILE_LOC.
 * Every host item contains a addr and a host name. Format: (addr) (hostname)
 * No error prevention of reading has been added. Hash tag notation not available.
 * Function modifies global variant hosts_list.
 */

void loadHosts()
{
	// Prepare reading
	//cout << "Start loading DNSRelay." << endl;
	std::ifstream fin;
	fin.open(HOST_FILE_LOC, std::ios::in);
	if(fin.is_open() == false)
	{
		//cout << "Failed to load DNSRelay file." << endl;
		return;
	}

	// Start reading 
	int count = 0;
	while(!fin.eof())
	{
		hosts_list[count] = new host_item;
		char *ip_addr = new char[20];
		fin >> ip_addr;
		inet_pton(AF_INET, ip_addr, &hosts_list[count]->ip_addr);
		if(hosts_list[count]->ip_addr == 0)
			hosts_list[count]->type = ADDR_BLOCKED;
		else
			hosts_list[count]->type = ADDR_CACHED;
		char *web_addr = new char[50];
		fin >> web_addr;
		hosts_list[count]->webaddr = web_addr;
		count++;
	}
	host_counter = count - 1;
	//cout << "DNSRelay successfully loaded." << endl;
	fin.close();
}

/*
 * UnpackDNSPacket converts a RFC1305 DNS request string into DNSPacket struct
 * Since Unpack job currently only does with queries from the host,
 * This function only dispatch header and query part of a 
 *
 */

DNSPacket *unpackDNSPacket(char *buf)
{
	char *cur_ptr = buf, *ret_ptr;
	
	DNSPacket *dns_packet = new DNSPacket;
		
	// Read DNS Header
	dns_packet->p_header = fromDNSHeader(cur_ptr, &ret_ptr);
	cur_ptr = ret_ptr;

	// Read DNS Query
	for(int i = 0; i < dns_packet->p_header->h_qdcount; i++)
	{
		dns_packet->p_qpointer[i] = fromDNSQuery(cur_ptr, &ret_ptr);
		cur_ptr = ret_ptr;
	}

	// Read DNS Response
	if(dns_packet->p_header->h_ancount > 0)
	{
		dns_packet->p_rpointer[0] = fromDNSResponse(cur_ptr, buf, &ret_ptr);
		cur_ptr = ret_ptr;
		dns_packet->p_header->h_ancount = 1;
	}

	//for(int i = 0; i < dns_packet->p_header->h_ancount; i++)
	//{
	//	dns_packet->p_rpointer[i] = fromDNSResponse(cur_ptr, buf, &ret_ptr);
	//	cur_ptr = ret_ptr;
	//}
	//dns_packet->p_header->h_ancount = 1;
	dns_packet->p_qr = (dns_packet->p_header->h_qr) ? Q_RESPONSE : Q_QUERY;
	
	return dns_packet;
}

/*
 * PackDNSPacket reads in a DNS packet, handles out a string in accordance with RFC1305.
 * This function treats query packets and response packets distinctively, 
 * since a query packet consists of a header and a query part
 * while a response packet consists of a header, a query part and a response part.
 * Function uses packet->p_type to tell whether it's a query or response.
 * Also returns the length of packet in *len
 * In:  DNSPacket *packet - Packet that need to be converted
 *      int *len		  - int pointer used to tell caller the length of formed string
 * Out: char* ret_string  - converted string of the DNSPacket
 */

char *packDNSPacket(DNSPacket *packet, int *len)
{
 	char *new_header = toDNSHeader(packet->p_header);
	
	//Convert Query part and Header part
	int tot_len = 0;
	char *ret_string = new char[1024];
	memcpy(ret_string, new_header, 12*sizeof(char));
	tot_len += 12;
	if(packet->p_header->h_qdcount == 1)
	{
		char *new_query = toDNSQuery(packet->p_qpointer[0]);
		memcpy(ret_string+tot_len, new_query, strlen(packet->p_qpointer[0]->q_qname) + 5);
		tot_len +=  strlen(packet->p_qpointer[0]->q_qname) + 5;
	}

	// Convert DNSResponse if needed (packet is a response)
	if(packet->p_qr == Q_RESPONSE && packet->p_header->h_ancount>0) 
	{
		char *new_response = toDNSResponse(packet->p_rpointer[0]);
		memcpy(ret_string+tot_len, new_response, strlen(packet->p_rpointer[0]->r_name) + 11 + packet->p_rpointer[0]->r_rdlength);
		tot_len += strlen(packet->p_rpointer[0]->r_name) + 11 + packet->p_rpointer[0]->r_rdlength;
	}
	*len = tot_len;
	return ret_string;
}

void DNSHandleThread(std::string upper_DNS_addr, SOCKET listen_socket, int t_id)
{
	THREADDEBUG << "Thread created." << std::endl;
	char *sendbuf, *dnsbuf;
	int sendbuflen = DEFAULT_BUFLEN;
	int iResult = 0;
	sendbuf = (char*)malloc(sendbuflen * sizeof(char));
	dnsbuf  = (char*)malloc(DEFAULT_BUFLEN * sizeof(char));

	//Create profile for upper DNS
	struct sockaddr_in servaddr;
	ZeroMemory(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, upper_DNS_addr.c_str(), &servaddr.sin_addr);

	struct sockaddr_in myaddr;
	ZeroMemory(&myaddr, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr= htonl(INADDR_ANY);
	myaddr.sin_port = htons(TOPORT(t_id));

	// Initialize upper dns server
	SOCKET upper_dns_socket = socket(AF_INET, SOCK_DGRAM, 0);
	//if(createUpperDNSSocket(&upper_dns_socket) != 0)
	//{
	//	THREADDEBUG << "Upper DNS socket creation failed." << std::endl;
	//	return;
	//}
	::bind(upper_dns_socket, (struct sockaddr*)&myaddr, sizeof(myaddr));

	DWORD dwBytesReturned = 0;
	BOOL bNewBehavior = FALSE;
	DWORD status;
	// disable  new behavior using
	// IOCTL: SIO_UDP_CONNRESET
	WSAIoctl(upper_dns_socket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior),
			NULL, 0, &dwBytesReturned, NULL, NULL);

	std::thread return_thread = std::thread(DNSReturnThread,upper_dns_socket, listen_socket, t_id);

	// Initialize cache list;
	while(1)
	{
		DNSRequest *req = NULL;
		while (req == NULL)
		{
			Sleep(20);
			req = getDNSRequest();
		}

		THREADDEBUG << "Got DNSReq" << std::endl;
		DNSPacket *recv_packet = req->packet;
		
		UINT32 ip_addr = 0;
		int wait_count = 0;
		WEBADDR_TYPE addr_type = getWebAddrType(recv_packet->p_qpointer[0]->q_qname, &ip_addr);
		THREADDEBUG << "Search type finished, type: " << addr_type << std::endl;

		if(recv_packet->p_qpointer[0]->q_qtype != 1) 
		{
			addr_type = ADDR_NOT_FOUND;
		}
		
		switch((int)addr_type)
		{
		case ADDR_BLOCKED:
		case ADDR_CACHED:
			{
				DNSPacket *result_packet = getDNSResult(recv_packet, ip_addr, addr_type);
				result_packet->p_header->h_id = req->old_id;

				sendbuf = packDNSPacket(result_packet, &sendbuflen);
				THREADDEBUG << "Start sending result to client" << std::endl;
				iResult = sendto(listen_socket, sendbuf, sendbuflen, 0, (struct sockaddr*)&(req->client_addr), req->client_addr_len);
				if(iResult == SOCKET_ERROR)
					THREADDEBUG << "sendto() failed with error code : " << WSAGetLastError() << std::endl;
				else
				{
					THREADDEBUG << "Bytes send to 127.0.0.1: " << iResult << std::endl;
				}
				DNSRequest *waste = finishDNSRequest(req->new_id);
			}
				break;
		case ADDR_NOT_FOUND:
			{
				int packet_length;
				u_short p_id = req->new_id;
				recv_packet->p_header->h_id  = p_id;
				char* send_string = packDNSPacket(recv_packet, &packet_length);

				THREADDEBUG << "Start consulting Upper DNS: " << upper_DNS_addr.c_str() << std::endl;
				iResult = sendto(upper_dns_socket, send_string, packet_length, 0, (struct sockaddr*)&servaddr,sizeof(servaddr));
				if(iResult == SOCKET_ERROR)
					THREADDEBUG <<  "sendto() failed with error code : " << WSAGetLastError() << std::endl;
			}
			break;
		}
	}
}

void DNSReturnThread(SOCKET upper_dns_socket, SOCKET listen_socket, int t_id)
{
	int iResult = 0;
	int sleeptime = 20, err = 0;
	struct sockaddr_in servaddr;
	int sendbuflen = DEFAULT_BUFLEN, dnsbuflen = DEFAULT_BUFLEN, servaddrlen = sizeof(servaddr);
	char *dnsbuf = new char[DEFAULT_BUFLEN];

	while(1)
	{
		iResult = recvfrom(upper_dns_socket, dnsbuf, DEFAULT_BUFLEN, 0, (struct sockaddr*)&servaddr, &servaddrlen); 			//Try to receive some data
		if(iResult == SOCKET_ERROR)											//Perhaps no data received
		{
			err = WSAGetLastError();											//Find out error type: Wrong or No Data
			if(err == WSAEWOULDBLOCK)											//Received no data, try again
			{
				Sleep(20);
				continue;
			}
			else													//Something has really gone wrong
			{
				THREADDEBUG << "! recvfrom_server() failed with error code : " << WSAGetLastError() << std::endl;
				break;
			}
		}
		else
		{
			THREADDEBUG << "Bytes received from ***: " << iResult << std::endl;		//We received something.
			//cout << "Get DNS Answer from 10.3.9.4" << endl;
			//p_id = req->old_id;
			int p_id = ntohs(*(u_short*)dnsbuf);
			DNSRequest *req = finishDNSRequest(p_id);
			*(u_short*)dnsbuf = htons(req->old_id);

			THREADDEBUG << "Start sending result to client" << std::endl;
			iResult = sendto(listen_socket, dnsbuf, sendbuflen, 0, (struct sockaddr*)&(req->client_addr), req->client_addr_len);
			if(iResult == SOCKET_ERROR)
				THREADDEBUG << "sendto() failed with error code : " << WSAGetLastError() << std::endl;
			else
			{
				THREADDEBUG << "Bytes send to 127.0.0.1: " << iResult << std::endl;
				analyzeResponsePacket(dnsbuf);
			}
		}
	}
}

DNSRequest* finishDNSRequest(int new_id)
{
	DNSRequest* req;
	pool_mutex.lock();
	req = request_pool[new_id].req;
	request_pool[new_id].available = true;
	pool_mutex.unlock();
	return req;
}


DNSRequest* getDNSRequest()
{
	DNSRequest* req = NULL;
	if(pool_mutex.try_lock())
	{
		for(int i = 0; i < MAX_REQ; i++)
		{
			if(!request_pool[i].available)
				if(request_pool[i].req->served == false)
				{
					req = request_pool[i].req;
					request_pool[i].req->served = true;
					break;
				}
		}
		pool_mutex.unlock();
	}
	return req;
}

int addDNSRequestPool(DNSRequest *req)
{
	pool_mutex.lock();
	int i;
	for(i = 0; i < MAX_REQ; i++)
	{
		if(request_pool[i].available)
		{
			request_pool[i].available = false;
			req->old_id = req->packet->p_header->h_id;
			req->new_id = i;
			request_pool[i].req = req;
			break;
		}
	}
	pool_mutex.unlock();
	return i;
}

void flushDnsCacheThread()
{
	while(1)
	{
		Sleep(30000);
		cache_mutex.lock();
		int i; 
		for(i = 0; i < cached_counter; i++)
		{
			if(cached_list[i]->occupied)
				cached_list[i]->ttl -= 60;
			if(cached_list[i]->ttl <= 0)
				cached_list[i]->occupied = false;
		}
		cache_mutex.unlock();
	}
}

void flushDNSRequestThread()
{
	while(1)
	{
		Sleep(10000);
		pool_mutex.lock();
		int i; 
		for(i = 0; i < MAX_REQ; i++)
		{
			if(!request_pool[i].available)
			{
				if(request_pool[i].req->ttl > 0)
					request_pool[i].req->ttl -= 100;
				if(request_pool[i].req->ttl <= 0)
					request_pool[i].available = true;
			}
		}
		pool_mutex.unlock();
	}
}

void analyzeResponsePacket(char *packet)
{
	DNSPacket *resp_packet = unpackDNSPacket(packet);
	for(int i = 0; i < resp_packet->p_header->h_ancount; i++)
	{
		if(resp_packet->p_rpointer[i]->r_type != 1)
			continue;
		int count = 0;
		
		while(cached_list[cached_counter]->occupied)
		{
			cached_counter = (cached_counter + 1) % MAX_CACHED_ITEM;
			count++;
			if(count > 400) break;
		}

		cached_item *store_cache_loc = cached_list[cached_counter];
		strcpy(store_cache_loc->webaddr, resp_packet->p_rpointer[i]->r_name);
		store_cache_loc->occupied = true;
		store_cache_loc->ttl = 600;
		store_cache_loc->ip_addr = ntohl(*((UINT32*)resp_packet->p_rpointer[i]->r_rdata));
		std::cout << "[CACHEADD]: Cache ID:" << cached_counter << std::endl;
	}
}