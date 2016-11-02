#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void hex_dump(unsigned char *buf, unsigned int buf_len)
{
	unsigned byte_counter = 0;
	int i;
	unsigned char *end = buf + buf_len;
	unsigned char *sotl; /* start of the line */
	unsigned char line_buf[16];

	while (buf < end) {
		memset(line_buf, 0, sizeof(line_buf));

		printf("%06X:   ", byte_counter);
		sotl = buf;

		for (i = 0; i < 8; i++) {
			if (buf < end) {
				line_buf[i] = *buf;
				printf("%02x ", *buf++);
			} else
				printf("   ");
		}

		printf("  ");

		for (i = 8; i < 16; i++) {
			if (buf < end) {
				line_buf[i] = *buf;
				printf("%02x ", *buf++);
			} else
				printf("   ");
		}

		printf("  |");
		for (i = 0; i < 16; i++) {
			if (isprint(line_buf[i]))
				printf("%c", line_buf[i]);
			else
				printf(".");
		}
		printf("|\n");

		byte_counter += 16;
	}
}

void dump_icmp_header(unsigned char *buf, unsigned len)
{
	printf("TODO: implement dump_icmp_header\n");
}

void dump_igmp_header(unsigned char *buf, unsigned len)
{
	printf("TODO: implement dump_igmp_header\n");
}

void dump_tcp_header(unsigned char *buf, unsigned len)
{
	if (len < 20) {
		printf("dump_udp_header(). len (%d) is less than minimal valid tcp header size.\n", len);
		return;
	}

	unsigned data_offset = buf[12] >> 4;

	printf("\tTCP header:\n");
	printf("\t\tbyte0-1.    Source Port: %d\n", (buf[0] << 8) | buf[1]);
	printf("\t\tbyte2-3.    Destination Port: %d\n", (buf[2] << 8) | buf[3]);
	printf("\t\tbyte4-7.    Sequence Number: %u\n",
			(buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7]);
	printf("\t\tbyte8-11.   Acknowledgement number: %u\n",
			(buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11]);
	printf("\t\tbyte12.     Data Offset: %d\n", buf[12] >> 4);
	printf("\t\tbyte12-13.  Flags (Control bits):\n");
	printf("\t\t\t\tNS: %d\n", buf[12] & 1);
	printf("\t\t\t\tCWR: %d\n", buf[13] >> 7);
	printf("\t\t\t\tECE: %d\n", (buf[13] >> 6) & 1);
	printf("\t\t\t\tURG: %d\n", (buf[13] >> 5) & 1);
	printf("\t\t\t\tACK: %d\n", (buf[13] >> 4) & 1);
	printf("\t\t\t\tPSH: %d\n", (buf[13] >> 3) & 1);
	printf("\t\t\t\tRST: %d\n", (buf[13] >> 2) & 1);
	printf("\t\t\t\tSYN: %d\n", (buf[13] >> 1) & 1);
	printf("\t\t\t\tFIN: %d\n", buf[13] & 1);
	printf("\t\tbyte14-15.  Window Size: %d\n", (buf[14] << 8) | buf[15]);
	printf("\t\tbyte16-17.  Checksum: 0x%02x%02x\n", buf[16], buf[17]);
	printf("\t\tbyte18-19.  Urgent Pointer: %d\n", (buf[18] << 8) | buf[19]);

	if (data_offset > 5) {
		printf("\t\t%d words of additional options...\n", data_offset - 5);
	}
}

void dump_udp_header(unsigned char *buf, unsigned len)
{
	if (len < 8) {
		printf("dump_udp_header(). len(%d) is less then minimal valid udp header size.\n", len);
		return;
	}

	printf("\tUDP header:\n");
	printf("\t\tbyte0-1.    Soure Port: %u\n", (buf[0] << 8) | buf[1]);
	printf("\t\tbyte2-3.    Destination Port: %u\n", (buf[2] << 8) | buf[3]);
	printf("\t\tbyte4-5.    Length: %u\n", (buf[4] << 8) | buf[5]);
	printf("\t\tbyte6-7.    Checksum: 0x%04x\n", (buf[6] << 8) | buf[7]);
}

void dump_arp_header(unsigned char *buf, unsigned len)
{
	printf("\tARP header:\n");
	printf("\t\t***IMPLEMENT IT***\n");
}

void dump_ipv6_header(unsigned char *buf, unsigned len)
{
	printf("TODO: implement dump_ipv6_header()\n");
}

void dump_ip_header(unsigned char *buf, unsigned len)
{
	if (len < 20) {
		printf("dump_ip_header(). len (%d) is less than minimal valid ip header size.\n", len);
		return;
	}

	int ihl = buf[0] & 0x0f;
	unsigned char protocol = buf[9];

	printf("\tIPv4 header:\n");
	printf("\t\tbyte0.      Version: %d\n", buf[0] >> 4);
	printf("\t\tbyte0.      IHL: %d\n", buf[0] & 0x0f);
	printf("\t\tbyte1.      DSCP: %d\n", buf[1] >> 2);
	printf("\t\tbyte1.      ECN: %d\n", buf[1] & 0x03);
	printf("\t\tbyte2-3.    Total Length: %d\n", (buf[2] << 8) | buf[3]);
	printf("\t\tbyte4-5.    Identification: %d\n", (buf[4] << 8) | buf[5]);
	printf("\t\tbyte6.      Flags:\n");
	printf("\t\t\t\tRESERVED (0): %d\n", buf[6] >> 7);
	printf("\t\t\t\tDF (Don't Fragment): %d\n", (buf[6] >> 6) & 1);
	printf("\t\t\t\tMF (More Fragments): %d\n", (buf[6] >> 5) & 1);
	printf("\t\tbyte6-7.    Fragment offset: %d\n", ((buf[6] & 0x1f) << 8) | buf[7]);
	printf("\t\tbyte8.      TTL: %d\n", buf[8]);
	printf("\t\tbyte9.      Protocol: %d\n", buf[9]);
	printf("\t\tbyte10-11.  Header checksum: 0x%04X\n", (buf[10] << 8) | buf[11]);
	printf("\t\tbyte12-15.  Source IP Address: %d.%d.%d.%d\n", buf[12], buf[13], buf[14], buf[15]);
	printf("\t\tbyte16-19.  Destination IP Address: %d.%d.%d.%d\n", buf[16], buf[17], buf[18], buf[19]);

	if (ihl > 5) {
	printf("\t\tSOME MORE %d words of OPTIONS...\n", ihl - 5);
	}

	switch (protocol) {
		case 1:
			dump_icmp_header(buf+ihl*4, len-ihl*4);
			break;
		case 2:
			dump_igmp_header(buf+ihl*4, len-ihl*4);
			break;
		case 6:
			dump_tcp_header(buf+ihl*4, len-ihl*4);
			break;
		case 17:
			dump_udp_header(buf+ihl*4, len-ihl*4);
			break;
	}
}

void dump_ethernet_header(unsigned char *buf, unsigned len);
void dump_vlan_header(unsigned char *buf, unsigned len);

void ethertype_switcher(unsigned char *buf, unsigned len)
{
	if (len < 2) {
		printf("ethertype_switcher(): len < 2. returning.\n");
		return;
	}

	unsigned short ethertype = (buf[0] << 8) | buf[1];
	switch (ethertype) {
		case 0x0800:
			dump_ip_header(buf+2, len-2);
			break;
		case 0x0806:
			dump_arp_header(buf+2, len-2);
			break;
		case 0x8100:
			dump_vlan_header(buf+2, len-2);
			break;
		case 0x86dd:
			dump_ipv6_header(buf+2, len-2);
			break;
	}
}

void dump_vlan_header(unsigned char *buf, unsigned len)
{
	printf("\tVLAN header:\n");
	printf("PCP/DEI/VID: 0x%02x%02x\n", buf[2], buf[3]);

	ethertype_switcher(buf+4, len-4);
}

// FIXME: I naively home that the len of buf is enought
// FIXME: check for VLAN ethernet frames (+4 bytes)
void dump_ethernet_header(unsigned char *buf, unsigned len)
{
	if (len < 12)
		return;

	unsigned short ethertype;
	printf("\tEthernet header:\n");
	printf("\t\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	printf("\t\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
	printf("\t\tEthertype/length: 0x%02x%02x\n", buf[12], buf[13]);
	ethertype = (buf[12] << 8) | buf[13];

	if (ethertype < 1500) {
		printf("Length: %d\n", ethertype);
		printf("***Do not know what packet type is enapsulated in.***\n");
	} else {
		ethertype_switcher(buf+12, len-12);
	}
}

void dump_packet(unsigned char *buf, unsigned len)
{
	static int counter = 0;
	printf("================================================================================\n");
	printf("Packet %d, len: %u:\n\n", counter++, len);
	hex_dump(buf, len);
	printf("\n");
	dump_ethernet_header(buf, len);
	printf("\n\n");
}

int main(int argc, char *argv[])
{
	unsigned char buf[2048];
	int packet_len;
	int packet_counter = 0;
	int packet_socket;

	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (packet_socket == -1) {
		perror("*FAILED* to create a AF_PACKET SOCK_RAW socket");
		exit(1);
	}

	while (1) {
		packet_len = read(packet_socket, buf, sizeof(buf));
		if (packet_len == -1) {
			if (errno == EAGAIN)
				continue;
			perror("*FAILED* to read from the socket");
			exit(1);
		}
		packet_counter++;

		dump_packet(buf, packet_len);
	}

	close(packet_socket);

	return 0;
}
