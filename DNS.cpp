#include "MainHeader.h"
#include "ReplyDNSResult.h"

const int SIP_UDP_CONNRESET = -1744830452;

#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR,12)

using namespace std;

host_item *hosts_list[MAX_HOST_ITEM];
int host_counter = 0;
u_short id_list[0x1000];
SOCKET upper_dns_socket;
 
int main()
{
	int iResult = 0;
	iResult = startWSA();
	loadHosts();
	
	SOCKET listen_socket;
	iResult = startDNSServer(&listen_socket);				//Start Server
	if (iResult == 1) return 255;
	iResult = connectToUpperDNS(&upper_dns_socket);				//Prepare connection to upper DNS
	if (iResult == 1) return 255;

	//Create profile(sockaddr) for topper DNS
	struct sockaddr_in servaddr;
	ZeroMemory(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, UPPER_DNS, &servaddr.sin_addr);

	char *ret_ptr = NULL, *recvbuf, *sendbuf, *dnsbuf;
	int recvbuflen = DEFAULT_BUFLEN, sendbuflen = DEFAULT_BUFLEN;
	recvbuf = (char*)malloc(recvbuflen * sizeof(char));
	sendbuf = (char*)malloc(recvbuflen * sizeof(char));
	dnsbuf  = (char*)malloc(recvbuflen * sizeof(char));
	do
	{
		struct sockaddr_in clientaddr;
		int client_addr_len = sizeof(clientaddr);
		memset(recvbuf, '\0', sizeof(recvbuf));
		ZeroMemory(&clientaddr, sizeof(clientaddr));

		
		DWORD dwBytesReturned = 0;
		BOOL bNewBehavior = FALSE;
		DWORD status;

		// disable  new behavior using
		// IOCTL: SIO_UDP_CONNRESET
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
				return(FALSE);
			}
			else
			{
				//cout << "WSAIoctl(SIO_UDP_CONNRESET) Error: " << dwErr << endl;
				return(FALSE);
			}
		}


		char *cur_pointer;
		//cout << "Waiting for data" << endl;
		iResult = recvfrom(listen_socket, recvbuf, recvbuflen, 0, (struct sockaddr*)&clientaddr, &client_addr_len);
		//iResult = recv(listen_socket, recvbuf, recvbuflen, 0);
		if (iResult == SOCKET_ERROR) {
			printf("recvfrom_client() error with code: %d\n", WSAGetLastError());
			break;
		}
		else{
			printf("Bytes received: %d\n", iResult);
			printf("Received Data: %s\n", recvbuf);
		}
		cur_pointer = recvbuf;

		DNSPacket *recv_packet = unpackDNSPacket(cur_pointer);
		UINT32 ip_addr = 0;
		int wait_count = 0;
		WEBADDR_TYPE addr_type = getWebAddrType(recv_packet->p_qpointer->q_qname, &ip_addr);
		//cout << "ADDR Type : " << addr_type << endl;
		
		//addr_type = ADDR_NOT_FOUND;
		switch((int)addr_type)
		{
		case ADDR_BLOCKED :
			{
				DNSPacket *result_packet = getDNSResult(recv_packet, ip_addr);
				sendbuf = packDNSPacket(result_packet, &sendbuflen);
			}
			break;
		case ADDR_CACHED:
			{
				DNSPacket *result_packet = getDNSResult(recv_packet, ip_addr);
				sendbuf = packDNSPacket(result_packet, &sendbuflen);
			}
			break;
		case ADDR_NOT_FOUND:
			{
				int packet_length;
				u_short p_id = assignNewID(recv_packet->p_header->h_id);
				recv_packet->p_header->h_id  = p_id;
				char* send_string = packDNSPacket(recv_packet, &packet_length);

				//cout << "Start consulting Upper DNS" << endl;
				iResult = sendto(upper_dns_socket, send_string, packet_length, 0, (struct sockaddr*)&servaddr,sizeof(servaddr));
				if(iResult == SOCKET_ERROR)
					printf("sendto() failed with error code : %d" , WSAGetLastError());

				struct sockaddr_in sender_w;
				int senderlen = sizeof(sender_w);
				int err, sleeptime = 10;								

				// wait_count serves as the implicator of total sleep time.
				// Sleeping time starts from 10 milliseconds, and *2 each time.
				// Maximum sleeping time = 10 + 20 + 40 + ... + 320 = 630ms
				// If nothing's been received in max sleeping time, the packet is treated as lost.
				// 
				while(wait_count < 6)
				{
					sendbuflen = recv(upper_dns_socket, dnsbuf, DEFAULT_BUFLEN, 0);			//Try to receive some data
					if(sendbuflen == SOCKET_ERROR)											//Perhaps no data received
					{
						err = WSAGetLastError();											//Find out error type: Wrong or No Data
						if(err == WSAEWOULDBLOCK)											//Received no data, try again
						{
							wait_count++;													//
							Sleep(sleeptime);
							//cout << "Got no reply. Waiting time before retry(ms): " << sleeptime << endl;
							sleeptime = sleeptime << 1;										//Multiply sleeptime by two
							continue;
						}
						else																//Something has really gone wrong
						{
							printf("recvfrom_server() failed with error code : %d" , WSAGetLastError());
							wait_count = 6;
							break;
						}
					}
					else
					{
						printf("Bytes received from 10.3.9.4: %d\n", sendbuflen);			//We received something.
						//cout << "Get DNS Answer from 10.3.9.4" << endl;
						p_id = getOriginalID(p_id);
						*(u_short*)dnsbuf = htons(p_id);
						sendbuf = dnsbuf;
						break;
					}
				}
			}
			break;
		}
		if(wait_count == 6)
		{
			//cout << "Upper DNS timeout. Ignore current DNS request" << endl;
			continue;
		}
		else
		{
			//cout << "Start sending result to client" << endl;
			iResult = sendto(listen_socket, sendbuf, sendbuflen, 0, (struct sockaddr*)&clientaddr, client_addr_len);
			if(iResult == SOCKET_ERROR)
				printf("sendto() failed with error code : %d\n" , WSAGetLastError());
			else
				printf("Bytes send to 127.0.0.1: %d\n", iResult);
		}
	}while(iResult >= 0);

	int s;
	cin >> s;
	return 0;
}

int startWSA()
{
	int iResult = 0;

	// Initalize Winsock
	WSADATA wsaData;
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
		//cout << "WSAStartup failed with error: " << iResult << endl;
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

DNSResponse *fromDNSResponse(char* src, char **ret_ptr)
{
	DNSResponse *new_r = new DNSResponse;
	int qname_length = 0;

	do
		qname_length++;							//Get QueryName length
	while(*(src + qname_length) != '\0');
	char *s = (char*)malloc(qname_length * sizeof(char));
	strcpy(s, src);
	new_r->r_name = s;
	
	src += qname_length;
	u_short *tmp = (u_short*)src;
	new_r->r_type = htons(*(tmp++));
	new_r->r_class = htons(*(tmp++));
	new_r->r_ttl = htonl(*((int*)tmp));
	tmp += 2;
	new_r->r_rdlength = htons(*(tmp++));

	src = (char*)tmp;
	s = (char*)malloc((new_r->r_rdlength + 1) * sizeof(char));
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
		//cout << "Socket creation failed with error: " << iResult << endl;
		WSACleanup();
		return 1;
	}
	//cout << "Socket created." << endl;

	struct sockaddr_in hints;
	hints.sin_family = AF_INET;
	hints.sin_addr.s_addr = INADDR_ANY;
	hints.sin_port = htons(DNS_PORT);

	iResult = bind(ListenSocket, (struct sockaddr*)&hints, sizeof(hints));
	if (iResult == SOCKET_ERROR) {
		//cout << "Binding failed with error: " <<  iResult << endl;
		WSACleanup();
		return 1;
	}
	//cout << "Binding succeed." << endl;

	*ret_socket = ListenSocket;
	return 0;
}

int connectToUpperDNS(SOCKET *ret_socket)
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

	//Set socket mode: unblocked
	iResult = ioctlsocket(send_socket,FIONBIO,(unsigned long *)&ul);			
	if(iResult == SOCKET_ERROR)
	{
		//cout << "Socket mode changing failed. ERROR " << iResult << endl;
		WSACleanup();
		return 1;
	}
	//cout << "Socket mode changed to unblocked." << endl;

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
	ifstream fin;
	fin.open(HOST_FILE_LOC, ios::in);
	if(fin.is_open() == false){
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
 * AssignNewID converts original packet ID to a new ID
 * to avoid sending requests with the same ID from different programs.
 * Original ID is stored in global variant id_list
 * The function stores original ID in the nth item of id_list
 * returns n, the newly assigned ID.
 */

u_short assignNewID(u_short ori_id)
{
	static int assign_number = 1;
	assign_number = (assign_number + 1) % 1000;
	id_list[assign_number] = ori_id;
	return assign_number;
}

u_short getOriginalID(u_short new_id)
{
	u_short ret_result = id_list[new_id];
	id_list[new_id] = 0;
	return ret_result;
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
	
	DNSPacket *req_packet = new DNSPacket;
		
	// Read DNS Header
	req_packet->p_header = fromDNSHeader(cur_ptr, &ret_ptr);
	cur_ptr = ret_ptr;

	// Read DNS Query
	req_packet->p_qpointer = fromDNSQuery(cur_ptr, &ret_ptr);
	cur_ptr = ret_ptr;

	req_packet->p_qr = Q_QUERY;

	return req_packet;
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
	//cout << "Packing addr: " << packet->p_qpointer->q_qname << endl;
	//cout << "Packing type: " << packet->p_qr << endl;
	//cout << "Packing id:   " << packet->p_header->h_id << endl;
 	char *new_header = toDNSHeader(packet->p_header);
	char *new_query = toDNSQuery(packet->p_qpointer);
	
	//Convert Query part and Header part
	int tot_len = 0;
	char *ret_string = new char[1024];
	memcpy(ret_string, new_header, 12*sizeof(char));
	tot_len += 12;
	memcpy(ret_string+tot_len, new_query, strlen(packet->p_qpointer->q_qname) + 5);
	tot_len +=  strlen(packet->p_qpointer->q_qname) + 5;

	// Convert DNSResponse if needed (packet is a response)
	if(packet->p_qr == Q_RESPONSE) 
	{
		char *new_response = toDNSResponse(packet->p_rpointer);
		memcpy(ret_string+tot_len, new_response, strlen(packet->p_rpointer->r_name) + 11 + packet->p_rpointer->r_rdlength);
		tot_len += strlen(packet->p_rpointer->r_name) + 11 + packet->p_rpointer->r_rdlength;
	}
	*len = tot_len;
	//cout << "Packing Complete" << endl;
	return ret_string;
}