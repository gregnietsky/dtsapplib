#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "include/dtsapp.h"

static PIP_ADAPTER_ADDRESSES get_adaptorinfo(int obufsize, int tries) {
	PIP_ADAPTER_ADDRESSES ainfo = NULL;
	int i = 1;
	unsigned long buflen;

	buflen = obufsize * i;

	do {
		if (!(ainfo = (IP_ADAPTER_ADDRESSES *)malloc(buflen))) {
			return NULL;
		}

	        if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, ainfo, &buflen) == ERROR_BUFFER_OVERFLOW) {
			free(ainfo);
			ainfo = NULL;
		} else {
			break;
		}

		i++;
	} while (i <= tries);

	return ainfo;
}

const char *inet_ntop(int af, const void *src, char *dest, socklen_t size) {
	union sockstruct sa;
	int res = 0;
	char serv[NI_MAXSERV];

	memset(&sa, 0, sizeof(sa));
	sa.ss.ss_family = af;

	switch(af) {
		case AF_INET:
			memcpy(&sa.sa4.sin_addr, src, sizeof(struct in_addr));
			res = getnameinfo(&sa.sa, sizeof(struct sockaddr_in), dest, size, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
			break;
		case AF_INET6:
			memcpy(&sa.sa6.sin6_addr, src, sizeof(struct in6_addr));
			res = getnameinfo(&sa.sa, sizeof(struct sockaddr_in6), dest, size, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
			break;
	}
	return (!res) ? dest : NULL;
}

static void free_ifinfo(void *data) {
	struct ifinfo *ifinf = (struct ifinfo*)data;

	if (ifinf->ifaddr) {
		free((void*)ifinf->ifaddr);
	}
	if (ifinf->ipv4addr) {
		free((void*)ifinf->ipv4addr);
	}
	if (ifinf->ipv6addr) {
		free((void*)ifinf->ipv6addr);
	}
}

struct ifinfo *get_ifinfo(const char *iface) {
	PIP_ADAPTER_ADDRESSES ainfo = NULL, cinfo;
	PIP_ADAPTER_UNICAST_ADDRESS pUnicast;
	struct sockaddr_storage *ss;
	char tmphn[NI_MAXHOST];
	char host4[NI_MAXHOST];
	char host6[NI_MAXHOST];
	int score4 = 0, score6 = 0, nscore;
	struct ifinfo *ifinf = NULL;

	if (!(ainfo = get_adaptorinfo(15000, 3))) {
		return NULL;
	}

	for(cinfo = ainfo; cinfo; cinfo = cinfo->Next) {
		if (strcmp(cinfo->AdapterName, iface)) {
			continue;
		}

		if (!(ifinf = (struct ifinfo*)objalloc(sizeof(*ifinf),free_ifinfo))) {
			return NULL;
		}

		ifinf->idx = (int)cinfo->IfIndex;

		if (cinfo->PhysicalAddressLength == 6) {
			unsigned int i;
			char tmp[4];
			char tmp2[18] = "";
			for (i = 0; i < cinfo->PhysicalAddressLength; i++) {
				if (i == (cinfo->PhysicalAddressLength - 1)) {
					sprintf(tmp,"%.2X", (int)cinfo->PhysicalAddress[i]);
				} else {
					sprintf(tmp,"%.2X:", (int)cinfo->PhysicalAddress[i]);
                		}
				strcat(tmp2, tmp);
			}
			ifinf->ifaddr = strdup(tmp2);
		} else {
			ifinf->ifaddr = NULL;
		}

		for (pUnicast = cinfo->FirstUnicastAddress; pUnicast ;pUnicast = pUnicast->Next) {
			ss = (struct sockaddr_storage*)pUnicast->Address.lpSockaddr;
			switch(ss->ss_family) {
				case AF_INET:
					nscore = score_ipv4((struct sockaddr_in*)ss, tmphn, NI_MAXHOST);
					if (score4 < nscore) {
						score4 = nscore;
						strcpy(host4, tmphn);
					}
					break;
				case AF_INET6:
					nscore = score_ipv6((struct sockaddr_in6*)ss, tmphn, NI_MAXHOST);
					if (score6 < nscore) {
						score6 = nscore;
						strcpy(host6, tmphn);
					}
					break;
			}
		}
		ifinf->ipv4addr = (strlenzero(host4)) ? NULL : strdup(host4);
		ifinf->ipv6addr = (strlenzero(host6)) ? NULL : strdup(host6);
		break;
	}

	if (ainfo) {
		free(ainfo);
	}

	return ifinf;
}
