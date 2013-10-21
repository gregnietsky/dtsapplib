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
  * @ingroup LIB-IP LIB-IP-IP4 LIB-IP-IP6
  * @brief IPv4 And IPv6 Utiliies*/

#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "include/dtsapp.h"

/** @brief Check if ipaddr is in a network
  * @ingroup LIB-IP-IP6
  * @param ipaddr To check.
  * @param network Network to check against.
  * @param bits Network length.
  * @returns 0 if the ipaddr is in the network.*/ 
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

/** @brief IP Protocol numbers
  * @ingroup LIB-IP*/
enum ipversion {
	IP_PROTO_V4 = 4,
	IP_PROTO_V6 = 6
};

/** @brief IPv4 header structur to cast a packet too.
  * @ingroup LIB-IP-IP4*/
struct pseudohdr {
	/** @brief Source address.*/
	uint32_t saddr;
	/** @brief Destination address.*/
	uint32_t daddr;
	/** @brief Zero byte.*/
	uint8_t	zero;
	/** @brief protocol.*/
	uint8_t proto;
	/** @brief Packet length.*/
	uint16_t len;
};

/** @brief Update the TCP checksum of a IPv4 packet.
  * @ingroup LIB-IP-IP4
  * @param pkt Packet to update TCP checksum.*/
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

/** @brief Update the UDP checksum of a IPv4 packet.
  * @ingroup LIB-IP-IP4
  * @param pkt Packet to update UDP checksum.*/
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

/** @brief Set the checksup of a IPv4 ICMP packet
  * @ingroup LIB-IP-IP4
  * @param pkt ICMP Packet to update.*/
extern void ipv4icmpchecksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;
	struct icmphdr *icmp = (struct icmphdr *)(pkt + (4 * ip->ihl));

	icmp->checksum = 0;
	icmp->checksum = checksum(icmp, ntohs(ip->tot_len) - (ip->ihl *4));
}

/** @brief Set the checksup of a IPv4 Packet
  * @ingroup LIB-IP-IP4
  * @param pkt Packet to update.*/
extern void ipv4checksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;

	ip->check = 0;
	ip->check = checksum(ip, (4 * ip->ihl));
}

/** @brief Update the checksum of a IPv4 packet.
  * @ingroup LIB-IP-IP4
  * @param pkt Packet buffer to update check.
  * @returns 0 on success.*/
extern int packetchecksumv4(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;

	ipv4checksum(pkt);

	switch(ip->protocol) {
		case IPPROTO_ICMP:
			ipv4icmpchecksum(pkt);
			break;
		case IPPROTO_TCP:
			ipv4tcpchecksum(pkt);
			break;
		case IPPROTO_UDP:
			ipv4udpchecksum(pkt);
			break;
		default:
			return (-1);
	}
	return (0);
}

/** @brief Prototype to check checksup on packet.
  * @ingroup LIB-IP-IP6
  * @param pkt Packet buffer to check.*/
extern int packetchecksumv6(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr *)pkt;
	switch(ip->protocol) {
		case IPPROTO_ICMP:
			break;
		case IPPROTO_TCP:
			break;
		case IPPROTO_UDP:
			break;
		default:
			return (-1);
	}
	return (0);
}

/** @brief Generic IPv4 and IPv6 Checksum
  * @ingroup LIB-IP
  * @param pkt Packet buffer to check.
  * @returns Checksum.*/
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

/** @brief Return the dotted quad notation subnet mask from a CIDR.
  * @ingroup LIB-IP-IP4
  * @param bitlen Subnet length bits.
  * @param buf Buffer to copy the subnet address too.
  * @param size Size of buffer.
  * @returns pointer to buffer on success or NULL.*/
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

/** @brief Return the network address
  * @ingroup LIB-IP-IP4
  * @note ipaddr will be truncated to network address based on cidr.
  * @param ipaddr Ipaddr to calculate for
  * @param cidr Length of the subnet bitmask.
  * @param buf Buffer that the result is placed in.
  * @param size Length of buffer.
  * @returns Pointer to buf with the result copied to buf.*/
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

/** @brief Get the first usable address
  * @ingroup LIB-IP-IP4
  * @note ipaddr will be truncated to network address based on cidr.
  * @param ipaddr Network address.
  * @param cidr Bits in the subnet mask.
  * @param buf Buffer that the result is placed in.
  * @param size Length of buffer.
  * @returns Pointer to buf with the result copied to buf.*/
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

/** @brief Return broadcast address
  * @ingroup LIB-IP-IP4
  * @note ipaddr will be truncated to network address based on cidr.
  * @param ipaddr Network address.
  * @param cidr CIDR subnet bit length.
  * @param buf Buffer to copy address too.
  * @param size Length of buffer.
  * @returns Pointer to buffer or NULL on error.*/
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

/** @brief Get the last usable address
  * @ingroup LIB-IP-IP4
  * @note ipaddr will be truncated to network address based on cidr.
  * @param ipaddr Network address.
  * @param cidr Bits in the subnet mask.
  * @param buf Buffer that the result is placed in.
  * @param size Length of buffer.
  * @returns Pointer to buf with the result copied to buf.*/
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

/** @brief Return the number of IP addresses in a given bitmask
  * @ingroup LIB-IP-IP4
  * @param bitlen Subnet bits (CIDR).
  * @returns Number of IP addreses including network and broadcast address.*/
extern uint32_t cidrcnt(int bitlen) {
	if (bitlen) {
		return pow(2, (32-bitlen));
	} else {
		return 0xFFFFFFFF;
	}
}

/** @brief Check IP against list of reserved IP's
  * @ingroup LIB-IP-IP4
  * @param ipaddr IP addr to check.
  * @returns 1 if its a private/resrved/not routed IP*/
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

/** @brief Return IPv6 to IPv4 Prefix fot the address.
  * @ingroup LIB-IP-IP6
  * @param ipaddr IPv4 Address to obtain mapping for
  * @returns 6to4 Address prefix.*/
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


/** @brief Check if a IP address is in a network
  * @ingroup LIB-IP-IP4
  * @note ipaddr will be truncated to network address based on cidr.
  * @param ip Network address to check against.
  * @param cidr Number of bits in the subnet.
  * @param test IP address to check
  * @returns 0 if test is not in the network ip/cidr.*/
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

/** @breif Randomally assign a SSM Multicast address.
  * @ingroup LIB-IP
  * param addr Ip address structure to fill out.*/
void mcast6_ip(struct in6_addr *addr) {
	int mip, rand;

	addr->s6_addr32[0] = htonl(0xFF350000);
	addr->s6_addr32[1] = 0;
	addr->s6_addr32[2] = 0;
	addr->s6_addr32[3] = 1 << 31;

	do {
		rand = genrand(&mip, 4);
	} while (!rand);

	addr->s6_addr32[3] = htonl(addr->s6_addr32[3] | mip);
}

/** @breif Randomally assign a SSM Multicast address.
  * @ingroup LIB-IP
  * param addr Ip address structure to fill out.*/
void mcast4_ip(struct in_addr *addr) {
	uint32_t mip, rand;

	do {
		rand = genrand(&mip, 3);
		mip >>= 8;
	} while (!rand || !(mip >> 8));
	mip |= 232 << 24;

 	addr->s_addr = htonl(mip);
}

