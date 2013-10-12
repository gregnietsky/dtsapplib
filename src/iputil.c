/*
Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za>
        http://www.distrotech.co.za

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/** @file
  * @brief IPv4 And IPv6 Utiliies
  * @defgroup LIB-IP IPv4 and IPv6 functions
  * @ingroup LIB
  * @brief Helper functions for various calculations
  * @addtogroup LIB-IP
  * @{*/

#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "include/dtsapp.h"

/*
 * Compare a ip address to a network address of bits long
 * in chunks of 32 bits returns 0 on match
 */
extern int checkipv6mask(const char *ipaddr, const char *network, uint8_t bits) {
	uint8_t cnt, bytelen, bitlen;
	uint32_t mask, res = 0;
	uint32_t *nw = (uint32_t *)network;
	uint32_t *ip = (uint32_t *)ipaddr;

	/*calculate significant bytes and bits outside boundry*/
	if ((bitlen = bits % 32)) {
		bytelen = (bits - bitlen) / 32;
		bytelen++;
	} else {
		bytelen = bits / 32;
	}

	/*end loop on first mismatch do not check last block*/
	for(cnt = 0; (!res && (cnt < (bytelen - 1))); cnt++) {
		res += nw[cnt] ^ ip[cnt];
	}

	/*process last block if no error sofar*/
	if (!res) {
		mask = (bitlen) ? htonl(~((1 << (32 - bitlen)) - 1)) : -1;
		res += (nw[cnt] & mask) ^ (ip[cnt] & mask);
	}

	return (res);
}

enum ipversion {
	IP_PROTO_V4 = 4,
	IP_PROTO_V6 = 6
};

struct pseudohdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t	zero;
	uint8_t proto;
	uint16_t len;
};

extern void ipv4tcpchecksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;
	struct tcphdr *tcp = (struct tcphdr *)(pkt + (4 * ip->ihl));
	uint16_t plen, csum;
	struct pseudohdr phdr;

	/* get tcp packet len*/
	plen = ntohs(ip->tot_len) - (4 * ip->ihl);
	tcp->check = 0;
	phdr.saddr = ip->saddr;
	phdr.daddr = ip->daddr;
	phdr.zero = 0;
	phdr.proto = ip->protocol;
	phdr.len = htons(plen);
	csum = checksum(&phdr, sizeof(phdr));
	tcp->check = checksum_add(csum, tcp, plen);
}

extern void ipv4udpchecksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;
	struct udphdr *udp = (struct udphdr *)(pkt + (4 * ip->ihl));
	uint16_t csum, plen;
	struct pseudohdr phdr;

	/* get tcp packet len*/
	plen = ntohs(ip->tot_len) - (4 * ip->ihl);
	udp->check = 0;
	phdr.saddr = ip->saddr;
	phdr.daddr = ip->daddr;
	phdr.zero = 0;
	phdr.proto = ip->protocol;
	phdr.len = htons(plen);
	csum = checksum(&phdr, sizeof(phdr));
	udp->check = checksum_add(csum, udp, plen);
}

extern void icmpchecksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;
	struct icmphdr *icmp = (struct icmphdr *)(pkt + (4 * ip->ihl));

	icmp->checksum = 0;
	icmp->checksum = checksum(icmp, ntohs(ip->tot_len) - (ip->ihl *4));
}

extern void ipv4checksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;

	ip->check = 0;
	ip->check = checksum(ip, (4 * ip->ihl));
}

extern int packetchecksumv4(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;

	ipv4checksum(pkt);

	switch(ip->protocol) {
		case IPPROTO_ICMP:
			icmpchecksum(pkt);
			break;
		case IPPROTO_TCP:
			ipv4tcpchecksum(pkt);
			break;
		case IPPROTO_UDP:
			ipv4udpchecksum(pkt);
			break;
		default
				:
			return (-1);
	}
	return (0);
}

extern int packetchecksumv6(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;
	switch(ip->protocol) {
		case IPPROTO_ICMP:
			break;
		case IPPROTO_TCP:
			break;
		case IPPROTO_UDP:
			break;
		default
				:
			return (-1);
	}
	return (0);
}

extern int packetchecksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;

	switch(ip->version) {
		case IP_PROTO_V4:
			return (packetchecksumv4(pkt));
			break;
		case IP_PROTO_V6:
			break;
	}
	return (-1);
}

extern const char *cidrtosn(int bitlen, const char *buf, int size) {
	uint32_t nm;

	if (!buf) {
		return NULL;
	}

	if (bitlen) {
		nm = ~((1 << (32-bitlen))-1);
	} else {
		nm = 0;
	}

	nm = htonl(nm);
	return inet_ntop(AF_INET, &nm, (char *)buf, size);
}

extern const char *getnetaddr(const char *ipaddr, int cidr, const char *buf, int size) {
	uint32_t ip;
	
	if (!buf) {
		return NULL;
	}

	inet_pton(AF_INET, ipaddr, &ip);
	if (cidr) {
		ip = ntohl(ip);
		ip = ip & ~((1 << (32-cidr))-1);
		ip = htonl(ip);		
	} else {
		ip = 0;
	}
	return inet_ntop(AF_INET, &ip, (char *)buf, size);
}

extern const char *getfirstaddr(const char *ipaddr, int cidr, const char *buf, int size) {
	uint32_t ip;
	
	if (!buf) {
		return NULL;
	}

	inet_pton(AF_INET, ipaddr, &ip);
	if (cidr) {
		ip = ntohl(ip);
		ip = ip & ~((1 << (32-cidr))-1);
		ip++;
		ip = htonl(ip);		
	} else {
		ip = 1;
	}
	return inet_ntop(AF_INET, &ip, (char *)buf, size);
}

extern const char *getbcaddr(const char *ipaddr, int cidr, const char *buf, int size) {
	uint32_t ip, mask;

	inet_pton(AF_INET, ipaddr, &ip);
	if (cidr) {
		mask = (1 << (32-cidr))-1;
		ip = ntohl(ip);
		ip = (ip & ~mask) | mask;
		ip = htonl(ip);		
	} else {
		ip = 0;
	}
	return inet_ntop(AF_INET, &ip, (char *)buf, size);
}

extern const char *getlastaddr(const char *ipaddr, int cidr, const char *buf, int size) {
	uint32_t ip, mask;

	inet_pton(AF_INET, ipaddr, &ip);
	if (cidr) {
		mask = (1 << (32-cidr))-1;
		ip = ntohl(ip);
		ip = (ip & ~mask) | mask;
		ip--;
		ip = htonl(ip);		
	} else {
		ip = 0;
	}
	return inet_ntop(AF_INET, &ip, (char *)buf, size);
}

extern uint32_t cidrcnt(int bitlen) {
	if (bitlen) {
		return pow(2, (32-bitlen));
	} else {
		return 0xFFFFFFFF;
	}
}

extern int reservedip(const char *ipaddr) {
	uint32_t ip;

	inet_pton(AF_INET, ipaddr, &ip);
	ip = ntohl(ip);

	if (!((0xe0000000 ^ ip) >> 28)) { /* 224/4*/
		return 1;
	} else if (!((0x00000000 ^ ip) >> 24)) { /* 0/8 */
		return 1;
	} else if (!((0x0a000000 ^ ip) >> 24)) { /* 10/8 */
		return 1;
	} else if (!((0x7f000000 ^ ip) >> 24)) { /* 127/8 */
		return 1;
	} else if (!((0x64400000 ^ ip) >> 22)) { /* 100.64/10 */
		return 1;
	} else if (!((0xac100000 ^ ip) >> 20)) { /* 172.16/12 */
		return 1;
	} else if (!((0xc6120000 ^ ip) >> 17)) { /* 198.18/15 */
		return 1;
	} else if (!((0xc0a80000 ^ ip) >> 16)) { /* 192.168/16 */
		return 1;
	} else if (!((0xa9fe0000 ^ ip) >> 16)) { /* 169.254/16 */
		return 1;
	} else if (!((0xc0000200 ^ ip) >> 8)) { /* 192.0.2/24 */
		return 1;
	} else if (!((0xc6336400 ^ ip) >> 8)) { /* 198.51.100/24 */
		return 1;
	} else if (!((0xcb007100 ^ ip) >> 8)) { /* 203.0.113/24 */
		return 1;
	}
	return 0;
}

extern char* ipv6to4prefix(const char *ipaddr) {
	uint32_t ip;
	uint8_t *ipa;
	char *pre6;

	if (!inet_pton(AF_INET, ipaddr, &ip)) {
		return NULL;
	}

	pre6 = malloc(10);
	ipa=(uint8_t*)&ip;
	snprintf(pre6, 10, "%02x%02x:%02x%02x", ipa[0], ipa[1], ipa[2], ipa[3]);
	return pre6;
}

extern int check_ipv4(const char* ip, int cidr, const char *test) {
	uint32_t ip1, ip2;

	inet_pton(AF_INET, ip, &ip1);
	inet_pton(AF_INET, test, &ip2);

	ip1 = ntohl(ip1) >> (32-cidr);
	ip2 = ntohl(ip2) >> (32-cidr);

	if (!(ip1 ^ ip2)) {
		return 1;
	} else {
		return 0;
	}
}

/** @}*/
