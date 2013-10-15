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
  * @ingroup LIB-NAT6
  * @brief Implementation of RFC6296
  * @addtogroup LIB-NAT6
  * @{*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "include/dtsapp.h"

struct natmap {
	uint16_t mask;
	uint16_t adjo;
	uint16_t adji;
	uint8_t ipre[16];
	uint8_t epre[16];
	uint32_t hash;
};

struct bucket_list *nptv6tbl = NULL;

static int32_t nptv6_hash(const void *data, int key) {
	const struct natmap *map = data;
	const void *hashkey = (key) ? data : map->ipre;
	int ret;

	ret = jenhash(hashkey, sizeof(map->ipre), 0);

	return (ret);
}

extern void rfc6296_map(struct natmap *map, struct in6_addr *ipaddr, int out) {
	uint16_t *addr_16 = (uint16_t *)&ipaddr->s6_addr;
	uint32_t calc;
	uint8_t cnt, *prefix, bitlen, bytelen;
	uint16_t adj;

	prefix = (out) ? map->epre : map->ipre;
	adj = (out) ? map->adjo : map->adji;

	if ((bitlen = map->mask % 8)) {
		bytelen = (map->mask - bitlen) / 8;
		bytelen++;
	} else {
		bytelen = map->mask / 8;
	}

	/*as per RFC we handle /48 and longer /48 changes are reflected in SN*/
	if ((bytelen == 6) && (~addr_16[3]) && (!bitlen)) {
		memcpy(&ipaddr->s6_addr, prefix, bytelen);
		calc = ntohs(addr_16[3]) + adj;
		addr_16[3] = htons((calc & 0xFFFF) + (calc >> 16));
		if (! ~addr_16[3]) {
			addr_16[3] = 0;
		}
	} else
		if ((bytelen > 6) && (bytelen < 15)) {
			/* find first non 0xFFFF word in lower 64 bits*/
			for(cnt = ((bytelen-1) >> 1) + 1; cnt < 8; cnt++) {
				if (! ~addr_16[cnt]) {
					continue;
				}
				if (bitlen) {
					ipaddr->s6_addr[bytelen-1] = prefix[bytelen-1] | (ipaddr->s6_addr[bytelen-1] & ((1 << (8 - bitlen)) -1));
				} else {
					ipaddr->s6_addr[bytelen-1] = prefix[bytelen-1];
				}
				memcpy(&ipaddr->s6_addr, prefix, bytelen - 1);
				calc = ntohs(addr_16[cnt]) + adj;
				addr_16[cnt] = htons((calc & 0xFFFF) + (calc >> 16));
				if (! ~addr_16[cnt]) {
					addr_16[cnt] = 0;
				}
				break;
			}
		}
}

extern int rfc6296_map_add(char *intaddr, char *extaddr) {
	struct natmap *map;
	uint16_t emask, imask, isum, esum, bytelen, bitlen;
	char inip[43], exip[43], *tmp2;
	struct in6_addr i6addr;
	uint32_t adj;

	strncpy(inip, intaddr, 43);
	if ((tmp2 = rindex(inip, '/'))) {
		tmp2[0] = '\0';
		tmp2++;
		imask = atoi(tmp2);
	} else {
		return (-1);
	}

	strncpy(exip, extaddr, 43);
	if ((tmp2 = rindex(exip, '/'))) {
		tmp2[0] = '\0';
		tmp2++;
		emask = atoi(tmp2);
	} else {
		return (-1);
	}

	map = objalloc(sizeof(*map), NULL);
	map->mask = (emask > imask) ? emask : imask;

	/*rfc says we must zero extend this is what we do here looking at each supplied len*/
	/*external range*/
	inet_pton(AF_INET6, exip, &i6addr);
	if ((bitlen = emask % 8)) {
		bytelen = (emask - bitlen) / 8;
		i6addr.s6_addr[bytelen] &= ~((1 << (8 - bitlen)) - 1);
		bytelen++;
	} else {
		bytelen = emask / 8;
	}
	memcpy(map->epre, &i6addr.s6_addr, bytelen);

	/*internal range*/
	inet_pton(AF_INET6, inip, &i6addr);
	if ((bitlen = imask % 8)) {
		bytelen = (imask - bitlen) / 8;
		i6addr.s6_addr[bytelen] &= ~((1 << (8 - bitlen)) - 1);
		bytelen++;
	} else {
		bytelen = imask / 8;
	}
	memcpy(map->ipre, &i6addr.s6_addr, bytelen);

	/*calculate the adjustments from checksums of prefixes*/
	if ((bitlen = map->mask % 8)) {
		bytelen = (map->mask - bitlen) / 8;
		bytelen++;
	} else {
		bytelen = map->mask / 8;
	}
	esum = ntohs(checksum(map->epre, bytelen));
	isum = ntohs(checksum(map->ipre, bytelen));

	/*outgoing transform*/
	adj = esum - isum;
	adj = (adj & 0xFFFF) + (adj >> 16);
	map->adjo = (uint16_t)adj;

	/*incoming transform*/
	adj = isum - esum;
	adj = (adj & 0xFFFF) + (adj >> 16);
	map->adji = (uint16_t)adj;

	if (!nptv6tbl && (!(nptv6tbl = create_bucketlist(5, nptv6_hash)))) {
		objunref(map);
		return (-1);
	}
	addtobucket(nptv6tbl, map);
	objunref(map);

	return (0);
}

extern void rfc6296_test(blist_cb callback, struct in6_addr *internal) {
	/*find and run map*/
	bucketlist_callback(nptv6tbl, callback, internal);

	objunref(nptv6tbl);
}

/** @}*/
