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

#include <netinet/in.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "include/dtsapp.h"
#include "libnetlink/include/libnetlink.h"
#include "libnetlink/include/ll_map.h"
#include "libnetlink/include/utils.h"

static struct rtnl_handle *nlh;

struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char			buf[1024];
};

struct ipaddr_req {
	struct nlmsghdr		n;
	struct ifaddrmsg	i;
	char			buf[1024];
};

static void nlhandle_free(void *data) {
	struct rtnl_handle *nlh = data;

	if (data) {
		rtnl_close(nlh);
	}
}

static struct rtnl_handle *nlhandle(int subscriptions) {
	struct rtnl_handle *nlh;

	if (!(nlh = objalloc(sizeof(*nlh), nlhandle_free)) || (rtnl_open(nlh, 0))) {
		if (nlh) {
			objunref(nlh);
		}
		return (NULL);
	}

	/*initilise the map*/
	ll_init_map(nlh, 0);
	objref(nlh);

	return (nlh);
}

extern void closenetlink() {
	if (nlh) {
		objunref(nlh);
	}
}

extern int get_iface_index(const char *ifname) {
	int ifindex;

	if (!objref(nlh) && !(nlh = nlhandle(0))) {
		return (0);
	}

	objlock(nlh);
	ll_init_map(nlh, 1);
	objunlock(nlh);

	ifindex = ll_name_to_index(ifname);

	objunref(nlh);
	return (ifindex);
}

/*
 * instruct the kernel to remove a link
 */
static int delete_interface(char *iface) {
	struct iplink_req *req;
	int ifindex, ret;

	/*check ifname grab a ref to nlh or open it*/
	if (strlenzero(iface) || (strlen(iface) > IFNAMSIZ) ||
	    (!objref(nlh) && !(nlh = nlhandle(0)))) {
		return (-1);
	}

	/*set the index of base interface*/
	if (!(ifindex = get_iface_index(iface))) {
		objunref(nlh);
		return (-1);
	}

	if (!(req = objalloc(sizeof(*req), NULL))) {
		objunref(nlh);
		return (-1);
	}

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_type = RTM_DELLINK;
	req->n.nlmsg_flags = NLM_F_REQUEST;

	/*config base/dev/mac*/
	req->i.ifi_index = ifindex;

	objlock(nlh);
	ret = rtnl_talk(nlh, &req->n, 0, 0, NULL);
	objunlock(nlh);

	objunref(nlh);
	objunref(req);

	return (ret);
}

extern int delete_kernvlan(char *ifname, int vid) {
	char iface[IFNAMSIZ+1];

	/*check ifname grab a ref to nlh or open it*/
	snprintf(iface, IFNAMSIZ, "%s.%i", ifname, vid);
	return (delete_interface(iface));
}

/*
 * instruct the kernel to create a VLAN
 */
extern int create_kernvlan(char *ifname, unsigned short vid) {
	struct iplink_req *req;
	char iface[IFNAMSIZ+1];
	struct rtattr *data, *linkinfo;
	char *type = "vlan";
	int ifindex, ret;

	if (strlenzero(ifname) || (strlen(ifname) > IFNAMSIZ) ||
	    (!objref(nlh) && !(nlh = nlhandle(0)))) {
		return (-1);
	}

	/*set the index of base interface*/
	if (!(ifindex = get_iface_index(ifname))) {
		objunref(nlh);
		return (-1);
	}

	if (!(req = objalloc(sizeof(*req), NULL))) {
		objunref(nlh);
		return (-1);
	}

	snprintf(iface, IFNAMSIZ, "%s.%i", ifname, vid);
	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_type = RTM_NEWLINK;
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST;

	/*config base/dev/mac*/
	addattr_l(&req->n, sizeof(*req), IFLA_LINK, &ifindex, sizeof(ifindex));
	addattr_l(&req->n, sizeof(*req), IFLA_IFNAME, iface, strlen(iface));

	/*type*/
	linkinfo  = NLMSG_TAIL(&req->n);
	addattr_l(&req->n, sizeof(*req), IFLA_LINKINFO, NULL, 0);
	addattr_l(&req->n, sizeof(*req), IFLA_INFO_KIND, type, strlen(type));

	/*vid*/
	data = NLMSG_TAIL(&req->n);
	addattr_l(&req->n, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	addattr_l(&req->n, sizeof(*req), IFLA_VLAN_ID, &vid, sizeof(vid));

	data->rta_len = (char*)NLMSG_TAIL(&req->n) - (char*)data;
	linkinfo->rta_len = (char*)NLMSG_TAIL(&req->n) - (char*)linkinfo;

	objlock(nlh);
	ret = rtnl_talk(nlh, &req->n, 0, 0, NULL);
	objunlock(nlh);

	objunref(nlh);
	objunref(req);

	return (ret);
}

/*
 * instruct the kernel to remove a VLAN
 */
extern int delete_kernmac(char *ifname) {

	return (delete_interface(ifname));
}

extern int create_kernmac(char *ifname, char *macdev, unsigned char *mac) {
	struct iplink_req *req;
	struct rtattr *data, *linkinfo;
	unsigned char lmac[ETH_ALEN];
	char *type = "macvlan";
	int ifindex, ret;

	if (strlenzero(ifname) || (strlen(ifname) > IFNAMSIZ) ||
	    strlenzero(macdev) || (strlen(macdev) > IFNAMSIZ) ||
	    (!objref(nlh) && !(nlh = nlhandle(0)))) {
		return (-1);
	}

	/*set the index of base interface*/
	if (!(ifindex = get_iface_index(ifname))) {
		objunref(nlh);
		return (-1);
	}

	if (!mac) {
		randhwaddr(lmac);
	} else {
		strncpy((char*)lmac, (char*)mac, ETH_ALEN);
	}

	if (!(req = objalloc(sizeof(*req), NULL))) {
		objunref(nlh);
		return (-1);
	}

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_type = RTM_NEWLINK;
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST;

	/*config base/dev/mac*/
	addattr_l(&req->n, sizeof(*req), IFLA_LINK, &ifindex, 4);
	addattr_l(&req->n, sizeof(*req), IFLA_IFNAME, macdev, strlen(macdev));
	addattr_l(&req->n, sizeof(*req), IFLA_ADDRESS, lmac, ETH_ALEN);

	/*type*/
	linkinfo  = NLMSG_TAIL(&req->n);
	addattr_l(&req->n, sizeof(*req), IFLA_LINKINFO, NULL, 0);
	addattr_l(&req->n, sizeof(*req), IFLA_INFO_KIND, type, strlen(type));

	/*mode*/
	data = NLMSG_TAIL(&req->n);
	addattr_l(&req->n, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	addattr32(&req->n, sizeof(*req), IFLA_MACVLAN_MODE, MACVLAN_MODE_PRIVATE);
	data->rta_len = (char*)NLMSG_TAIL(&req->n) - (char*)data;
	linkinfo->rta_len = (char*)NLMSG_TAIL(&req->n) - (char*)linkinfo;

	objlock(nlh);
	ret = rtnl_talk(nlh, &req->n, 0, 0, NULL);
	objunlock(nlh);

	objunref(nlh);
	objunref(req);

	return (ret);
}

extern int set_interface_flags(int ifindex, int set, int clear) {
	struct iplink_req *req;
	int flags;

	if (!objref(nlh) && !(nlh = nlhandle(0))) {
		return (-1);
	}

	flags = ll_index_to_flags(ifindex);

	flags |= set;
	flags &= ~(clear);

	if (!(req = objalloc(sizeof(*req), NULL))) {
		objunref(nlh);
		return (-1);
	}

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_type = RTM_NEWLINK;
	req->n.nlmsg_flags = NLM_F_REQUEST;

	/*config base/dev/mac*/
	req->i.ifi_index = ifindex;
	req->i.ifi_flags = flags;
	req->i.ifi_change = set | clear;

	objlock(nlh);
	rtnl_talk(nlh, &req->n, 0, 0, NULL);
	objunlock(nlh);

	objunref(nlh);
	objunref(req);
	return (0);
}

extern int set_interface_addr(int ifindex, const unsigned char *hwaddr) {
	struct iplink_req *req;

	if ((!objref(nlh) && !(nlh = nlhandle(0)))) {
		return (-1);
	}

	if (!(req = objalloc(sizeof(*req), NULL))) {
		objunref(nlh);
		return (-1);
	}

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_type = RTM_NEWLINK;
	req->n.nlmsg_flags = NLM_F_REQUEST;
	req->i.ifi_index = ifindex;

	/*config base/dev/mac*/
	addattr_l(&req->n, sizeof(*req), IFLA_ADDRESS, hwaddr, ETH_ALEN);

	objlock(nlh);
	rtnl_talk(nlh, &req->n, 0, 0, NULL);
	objunlock(nlh);

	objunref(nlh);
	objunref(req);
	return (0);
}

extern int set_interface_name(int ifindex, const char *name) {
	struct iplink_req *req;

	if ((!objref(nlh) && !(nlh = nlhandle(0)))) {
		return (-1);
	}

	if (!(req = objalloc(sizeof(*req), NULL))) {
		objunref(nlh);
		return (-1);
	}

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_type = RTM_NEWLINK;
	req->n.nlmsg_flags = NLM_F_REQUEST;
	req->i.ifi_index = ifindex;

	addattr_l(&req->n, sizeof(*req), IFLA_IFNAME, name, strlen((char *)name));

	objlock(nlh);
	rtnl_talk(nlh, &req->n, 0, 0, NULL);
	objunlock(nlh);

	objunref(nlh);
	objunref(req);
	return (0);
}

/*
 * bind to device fd may be a existing socket
 */
extern int interface_bind(char *iface, int protocol, int flags) {
	struct sockaddr_ll sll;
	int proto = htons(protocol);
	int fd, ifindex;

	/*set the network dev up*/
	if (!(ifindex = get_iface_index(iface))) {
		return (-1);
	}
	set_interface_flags(ifindex, IFF_UP | IFF_RUNNING, 0);

	/* open network raw socket */
	if ((fd = socket(PF_PACKET, SOCK_RAW,  proto)) < 0) {
		return (-1);
	}

	/*bind to the interface*/
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = proto;
	sll.sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
		perror("bind failed");
		close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * this method is sourced from the following IEEE publication
 * Guidelines for 64-bit Global Identifier (EUI-64TM) Registration Authority
 * mac48 is char[ETH_ALEN] eui64 is char[8]
 */
extern int eui48to64(unsigned char *mac48, unsigned char *eui64) {
	eui64[0] = (mac48[0] & 0xFE) ^ 0x02; /*clear multicast bit and flip local asignment*/
	eui64[1] = mac48[1];
	eui64[2] = mac48[2];
	eui64[3] = 0xFF;
	eui64[4] = 0xFE;
	eui64[5] = mac48[3];
	eui64[6] = mac48[4];
	eui64[7] = mac48[5];

	return (0);
}

/*
 * Unique Local IPv6 Unicast Addresses RFC 4193
 * buff is char[6]
 */
extern int get_ip6_addrprefix(const char *iface, unsigned char *prefix) {
	uint64_t ntpts;
	unsigned char eui64[8];
	unsigned char sha1[20];
	unsigned char mac48[ETH_ALEN];
	struct timeval tv;

	if (ifhwaddr(iface, mac48)) {
		return (-1);
	}

	gettimeofday(&tv, NULL);
	ntpts = tvtontp64(&tv);

	eui48to64(mac48, eui64);
	sha1sum2(sha1, (void*)&ntpts, sizeof(ntpts), (void*)eui64, sizeof(eui64));

	prefix[0] = 0xFD; /*0xFC | 0x01 FC00/7 with local bit set [8th bit]*/
	memcpy(prefix + 1, sha1+15, 5); /*LSD 40 bits of the SHA hash*/

	return (0);
}

/*
 * create random MAC address
 */
extern void randhwaddr(unsigned char *addr) {
	genrand(addr, ETH_ALEN);
	addr [0] &= 0xfe;       /* clear multicast bit */
	addr [0] |= 0x02;       /* set local assignment bit (IEEE802) */
}

extern int create_tun(const char *ifname, const unsigned char *hwaddr, int flags) {
	struct ifreq ifr;
	int fd, ifindex;
	char *tundev = "/dev/net/tun";

	/* open the tun/tap clone dev*/
 	if ((fd = open(tundev, O_RDWR)) < 0) {
		return (-1);
 	}

	/* configure the device*/
 	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0 ) {
		perror("ioctl(TUNSETIFF) failed\n");
		close(fd);
		return (-1);
	}

	if (!(ifindex = get_iface_index(ifname))) {
		return (-1);
	}

	/* set the MAC address*/
	if (hwaddr) {
		set_interface_addr(ifindex, hwaddr);
	}

	/*set the network dev up*/
	set_interface_flags(ifindex, IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_BROADCAST, 0);

	return (fd);
}

extern int ifdown(const char *ifname, int flags) {
	int ifindex;

	/*down the device*/
	if (!(ifindex = get_iface_index(ifname))) {
		return (-1);
	}

	/*set the network dev up*/
	set_interface_flags(ifindex, 0, IFF_UP | IFF_RUNNING | flags);

	return (0);
}

extern int ifup(const char *ifname, int flags) {
	int ifindex;

	/*down the device*/
	if (!(ifindex = get_iface_index(ifname))) {
		return (-1);
	}

	/*set the network dev up*/
	set_interface_flags(ifindex, IFF_UP | IFF_RUNNING | flags, 0);

	return (0);
}

extern int ifrename(const char *oldname, const char *newname) {
	int ifindex;

	ifdown(oldname, 0);

	if (!(ifindex = get_iface_index(oldname))) {
		return (-1);
	}
	set_interface_name(ifindex, newname);

	return (0);
}

extern int ifhwaddr(const char *ifname, unsigned char *hwaddr) {
	int ifindex;

	if (!hwaddr || strlenzero(ifname) || (strlen(ifname) > IFNAMSIZ) ||
	    (!objref(nlh) && !(nlh = nlhandle(0)))) {
		return (-1);
	}

	/*set the index of base interface*/
	if (!(ifindex = get_iface_index(ifname))) {
		objunref(nlh);
		return (-1);
	}

	ll_index_to_addr(ifindex, hwaddr, ETH_ALEN);
	objunref(nlh);
	return (0);
}


extern int set_interface_ipaddr(char *ifname, char *ipaddr) {
	struct ipaddr_req *req;
	inet_prefix lcl;
	int ifindex, bcast;

	if ((!objref(nlh) && !(nlh = nlhandle(0)))) {
		return (-1);
	}

	if (!(req = objalloc(sizeof(*req), NULL))) {
		objunref(nlh);
		return (-1);
	}

	/*set the index of base interface*/
	if (!(ifindex = get_iface_index(ifname))) {
		objunref(nlh);
		return (-1);
	}

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req->n.nlmsg_type = RTM_NEWADDR;
	req->n.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;

	req->i.ifa_scope = RT_SCOPE_HOST;
	req->i.ifa_index = ifindex;

	get_prefix(&lcl, ipaddr, AF_UNSPEC);
	req->i.ifa_family = lcl.family;
	req->i.ifa_prefixlen = lcl.bitlen;

	addattr_l(&req->n, sizeof(*req), IFA_LOCAL, &lcl.data, lcl.bytelen);
	addattr_l(&req->n, sizeof(*req), IFA_ADDRESS, &lcl.data, lcl.bytelen);
	if (lcl.family == AF_INET) {
		bcast = htonl((1 << (32 - lcl.bitlen)) - 1);
		addattr32(&req->n, sizeof(*req), IFA_BROADCAST, lcl.data[0] | bcast);
	}

	objlock(nlh);
	rtnl_talk(nlh, &req->n, 0, 0, NULL);
	objunlock(nlh);

	objunref(nlh);
	objunref(req);
	return (0);
}
