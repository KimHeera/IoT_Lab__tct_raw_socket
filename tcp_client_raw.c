#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZE 1024
#define DATA_SIZE 20
#define DG_SIZE 2048

// Before run this code, execute the command below 
// $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
void mkSYNpkt(struct sockaddr_in *saddr, struct sockaddr_in *daddr, char **pkt, int *pkt_len);
int recvSYNACKpkt(int sock, char *buf, size_t buf_len, struct sockaddr_in *saddr);
void mkACKpkt(struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint32_t seq, uint32_t ackSeq, char **pkt, int *pkt_len);
void createDataPkt(struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint32_t seq, uint32_t ackSeq, char *data, int data_len, char **pkt, int *pkt_len, int *pktId);
void default_ipSet(struct iphdr *ip, struct sockaddr_in *saddr, struct sockaddr_in *daddr);
void default_tcpSet(struct tcphdr *tcp, struct sockaddr_in *saddr, struct sockaddr_in *daddr);

// TODO: pseudo header needed for tcp header checksum calculation
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

// TODO: Define checksum function which returns unsigned short value 
unsigned short checksum(char *data, unsigned length)
{
	unsigned sum = 0;
	int i;
	for (i = 0; i < length - 1; i+=2){
		unsigned short tmp = *(unsigned short *)&data[i]; //pointer casting
		sum += tmp; 
	}

	if(length & 1) //Is length odd?
	{	//data에 남은 1 byte 처리
		unsigned short tmp = (unsigned char)data[i];
		sum += tmp;
	}

	while(sum >> 16){
		sum = (sum & 0xFFFF) + (sum >> 16);
		// 0xffff는 16bit의 모든 bit이 1로 설정된 값
		//(sum & 0xFFFF) -> sum의 하위 16bits를 가져옴
		// (sum >> 16) -> sum의 상위 16bits를 가져옴
	}
	return ~sum;
}

// TODO 
int main(int argc, char *argv[])
{

	if (argc != 4)
	{
		printf("Usage: %s <Source IP> <Destination IP> <Destination Port>\n", argv[0]);
		return 1;
	}

	srand(time(NULL));

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock == -1)
	{
		perror("socket");
        exit(EXIT_FAILURE);
	}

	// Source IP
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(rand() % 65535); // random client port
	if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1)
	{
		perror("Source IP configuration failed\n");
		exit(EXIT_FAILURE);
	}

	// Destination IP and Port 
	struct sockaddr_in daddr;
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(atoi(argv[3]));
	if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1)
	{
		perror("Destination IP and Port configuration failed");
		exit(EXIT_FAILURE);
	}

	// Tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1) // IP_HDRINCL -> Allows users to directly manipulate IP headers.
	{
		perror("setsockopt(IP_HDRINCL, 1)");
		exit(EXIT_FAILURE);
	}

	// TCP Three-way Handshaking
	char *pkt;
	int pkt_len, sendSYN;
	// Step 1. Send SYN (no need to use TCP options)
	mkSYNpkt(&saddr, &daddr, &pkt, &pkt_len);
	if((sendSYN = sendto(sock, pkt, pkt_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
		printf("sendto() falied. \n");

	// Step 2. Receive SYNs-ACK
	char recvBuf[BUF_SIZE];
	int recvSYNACK = recvSYNACKpkt(sock, recvBuf, sizeof(recvBuf), &saddr);
	if (recvSYNACK <= 0)
	{
		printf("receive_from() failed\n");
	}

	// Step 3. Send ACK
	uint32_t seqNum, ackNum;
	uint32_t tmpSeq, tmpAck;

	memcpy(&tmpSeq, recvBuf + 24, 4);
	memcpy(&tmpAck, recvBuf + 28, 4);
	seqNum = ntohl(tmpSeq);
	ackNum = ntohl(tmpAck);

	uint32_t NewSeqNum = seqNum + 1;
	int sendACK;

	mkACKpkt(&saddr, &daddr, ackNum, NewSeqNum, &pkt, &pkt_len);
	if ((sendACK = sendto(sock, pkt, pkt_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr))) == -1)
		printf("sendto() failed\n");

	int sendData = 0;
	int pktId = 0;
	// Data transfer
	while (1)
	{
		char message[BUF_SIZE] = {
			0,
		};

		fputs("Input message(Q to quit): ", stdout);
		fgets(message, BUF_SIZE, stdin);

		if (!strcmp(message, "q\n") || !strcmp(message, "Q\n"))
			break;

		// Step 4. Send an application message (with PSH and ACK flag)!
		createDataPkt(&saddr, &daddr, ackNum, NewSeqNum, message, strlen(message), &pkt, &pkt_len, &pktId);
		if((sendData = sendto(sock, pkt, pkt_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr))) == -1)
			printf("sendto() failed\n");

		// Step 5. Receive ACK
		recvSYNACK = recvSYNACKpkt(sock, recvBuf, sizeof(recvBuf), &saddr);
		if (recvSYNACK <= 0)
		{
			printf("receive_from() failed\n");
		}
		memcpy(&tmpSeq, recvBuf + 24, 4);
		memcpy(&tmpAck, recvBuf + 28, 4);
		NewSeqNum = ntohl(tmpSeq);
		ackNum = ntohl(tmpAck);
	}

	close(sock);
	return 0;
}

void default_ipSet(struct iphdr *ip, struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
	ip->version = 4; // IPv4
	ip->ihl = 5;	 // header length. 5 * 4 = 20 bytes.
	ip->tos = 0;	 // pkt priority don't care ~
	ip->id = htonl(rand() % 65535);
	ip->frag_off = htons(1 << 14);								// flag를 DF사용하려면? shift! (1 << 14)
	ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // total 40 bytes
	ip->ttl = 64;												// ordinary set
	ip->protocol = IPPROTO_TCP;									// upper layer protocol is TCP. 6
	ip->check = 0;												// after set
	ip->saddr = saddr->sin_addr.s_addr;
	ip->daddr = daddr->sin_addr.s_addr;
}
void default_tcpSet(struct tcphdr *tcp, struct sockaddr_in *saddr, struct sockaddr_in *daddr){
	tcp->source = saddr->sin_port;
	tcp->dest = daddr->sin_port;
	tcp->fin = 0;
	tcp->syn = 0; // this is syn pkt
	tcp->rst = 0; // data transfer 할 때는 psh와 ack를 1로 set
	tcp->psh = 0;
	tcp->ack = 0;
	tcp->urg = 0;
	tcp->window = htons(16000);
	tcp->check = 0;	  // after set
	tcp->urg_ptr = 0; // not use
}


void mkSYNpkt(struct sockaddr_in *saddr, struct sockaddr_in *daddr, char **pkt, int *pkt_len){
	char *datagram = calloc(DG_SIZE, sizeof(char));

	struct iphdr *ip = (struct iphdr *)datagram;
	struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct iphdr));

	// ip header config set
	default_ipSet(ip, saddr, daddr);

	// tcp header config set
	default_tcpSet(tcp, saddr, daddr);
	tcp->seq = htonl(rand() % 4294967285); // 4294967285 = 2^32 - 1. seq field is 32 bits. 중복 최소화!
	tcp->ack_seq = htonl(0); //this pkt is not ack
	tcp->doff = 5; //data offset. 5 * 4 = 20 bytes
	tcp->syn = 1; // this is syn pkts

	struct pseudo_header ph;
	ph.source_address = saddr->sin_addr.s_addr;
	ph.dest_address = daddr->sin_addr.s_addr;
	ph.placeholder = 0;
	ph.protocol = IPPROTO_TCP;
	ph.tcp_length = htons(sizeof(struct tcphdr));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	char *pseudogram = malloc(sizeof(char) * psize);

	memcpy(pseudogram, (char *)&ph, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

	tcp->check = checksum((char *)pseudogram, psize);
	ip->check = checksum((char *)datagram, ip->tot_len);

	*pkt = datagram;
	*pkt_len = ip->tot_len;
	free(pseudogram);
}

int recvSYNACKpkt(int sock, char* buf, size_t buf_len, struct sockaddr_in *saddr){
	int recvSYNACK;
	unsigned short dport; //int로 선언하지 않는 이유는 음수 허용 X, 메모리 공간도 더 많이 필요함.

	recvSYNACK = recvfrom(sock, buf, buf_len, 0, NULL, NULL);
	memcpy(&dport, buf + 22, sizeof(dport));

	while(dport != saddr->sin_port){
		if (recvSYNACK < 0)
			break;

		recvSYNACK = recvfrom(sock, buf, buf_len, 0, NULL, NULL);
		memcpy(&dport, buf + 22, sizeof(dport));
	}
	return recvSYNACK;
}

void mkACKpkt(struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint32_t seq, uint32_t ackSeq, char **pkt, int *pkt_len){
	char *datagram = calloc(DG_SIZE, sizeof(char));

	struct iphdr *ip = (struct iphdr *)datagram;
	struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct iphdr));

	// ip header config set
	default_ipSet(ip, saddr, daddr);

	// tcp header config set
	default_tcpSet(tcp, saddr, daddr);
	tcp->seq = htonl(seq);	
	tcp->ack_seq = htonl(ackSeq); 
	tcp->doff = 5;	// data offset. 5 * 4 = 20 bytes
	tcp->ack = 1;

	struct pseudo_header ph;
	ph.source_address = saddr->sin_addr.s_addr;
	ph.dest_address = daddr->sin_addr.s_addr;
	ph.placeholder = 0;
	ph.protocol = IPPROTO_TCP;
	ph.tcp_length = htons(sizeof(struct tcphdr));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	char *pseudogram = malloc(sizeof(char) * psize);

	memcpy(pseudogram, (char *)&ph, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

	tcp->check = checksum((char *)pseudogram, psize);
	ip->check = checksum((char *)datagram, ip->tot_len);

	*pkt = datagram;
	*pkt_len = ip->tot_len;
	free(pseudogram);
}

void createDataPkt(struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint32_t seq, uint32_t ackSeq, char *data, int data_len, char **pkt, int *pkt_len, int *pktId)
{
	char *datagram = calloc(DG_SIZE, sizeof(char));

	struct iphdr *ip = (struct iphdr *)datagram;
	struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct iphdr));

	char *payload = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_SIZE;
	memcpy(payload, data, data_len);

	// ip header config set
	default_ipSet(ip, saddr, daddr);
	ip->id = htons((*pktId)++);		
	ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_SIZE + data_len; 
	
	// tcp header config set
	default_tcpSet(tcp, saddr, daddr);
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(ackSeq);
	tcp->doff = 10; // data offset. 10 * 4 = 40 bytes
	tcp->psh = 1;
	tcp->ack = 1;

	struct pseudo_header ph;
	ph.source_address = saddr->sin_addr.s_addr;
	ph.dest_address = daddr->sin_addr.s_addr;
	ph.placeholder = 0;
	ph.protocol = IPPROTO_TCP;
	ph.tcp_length = htons(sizeof(struct tcphdr) + data_len + DATA_SIZE);

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + DATA_SIZE + data_len;
	char *pseudogram = malloc(sizeof(char) * psize);

	memcpy(pseudogram, (char *)&ph, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr) + DATA_SIZE + data_len);

	tcp->check = checksum((char *)pseudogram, psize);
	ip->check = checksum((char *)datagram, ip->tot_len);

	*pkt = datagram;
	*pkt_len = ip->tot_len;
	free(pseudogram);
}