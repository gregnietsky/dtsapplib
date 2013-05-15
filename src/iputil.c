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
	uint32_t *nw = (uint32_t*)network;
	uint32_t *ip = (uint32_t*)ipaddr;

	/*calculate significant bytes and bits outside boundry*/
	if ((bitlen = bits % 32)) {
		bytelen = (bits - bitlen) / 32;
		bytelen++;
	} else {
		bytelen = bits / 32;
	}

	/*end loop on first mismatch do not check last block*/
	for(cnt = 0;(!res && (cnt < (bytelen - 1)));cnt++) {
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
	struct iphdr *ip = (struct iphdr*)pkt;
	struct tcphdr *tcp = (struct tcphdr*)(pkt + (4 * ip->ihl));
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
	struct iphdr *ip = (struct iphdr*)pkt;
	struct udphdr *udp = (struct udphdr*)(pkt + (4 * ip->ihl));
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
	struct iphdr *ip = (struct iphdr*)pkt;
	struct icmphdr *icmp = (struct icmphdr*)(pkt + (4 * ip->ihl));

	icmp->checksum = 0;
	icmp->checksum = checksum(icmp, ntohs(ip->tot_len) - (ip->ihl *4));
}

extern void ipv4checksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr*)pkt;

	ip->check = 0;
	ip->check = checksum(ip, (4 * ip->ihl));
}

extern int packetchecksumv4(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr*)pkt;

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
		default:
			return (-1);
	}
	return (0);
}

extern int packetchecksumv6(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr*)pkt;
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

extern int packetchecksum(uint8_t *pkt) {
	struct iphdr *ip = (struct iphdr*)pkt;

	switch(ip->version) {
		case IP_PROTO_V4:
			return (packetchecksumv4(pkt));
			break;
		case IP_PROTO_V6:
			break;
	}
	return (-1);
}
