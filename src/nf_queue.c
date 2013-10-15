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
  * @ingroup LIB-NF-Q
  * @brief Linux netfilter queue interface
  * @addtogroup LIB-NF-Q
  * @{*/

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "include/dtsapp.h"
#include "include/private.h"

enum NF_QUEUE_FLAGS {
	NFQUEUE_DONE	= 1 << 0
};

struct nfq_struct {
	struct nfq_handle *h;
	uint16_t pf;
	int fd;
	int flags;
};

struct nfq_queue {
	struct nfq_struct *nfq;
	struct nfq_q_handle *qh;
	nfqueue_cb cb;
	void *data;
	uint16_t num;
};

struct nfq_list {
	struct bucket_list *queues;
}  *nfqueues = NULL;

static int32_t nfqueue_hash(const void *data, int key) {
	const struct nfq_struct *nfq = data;
	const uint16_t *hashkey = (key) ? data : &nfq->pf;

	return (*hashkey);
}

static void nfqueues_close(void *data) {

	if (nfqueues->queues) {
		objunref(nfqueues->queues);
	}
	nfqueues = NULL;
}

static void nfqueue_close(void *data) {
	struct nfq_struct *nfq = data;

	nfq_unbind_pf(nfq->h, nfq->pf);
	nfq_close(nfq->h);
	objunref(nfqueues);
}

static void nfqueue_close_q(void *data) {
	struct nfq_queue *nfq_q = data;

	if (nfq_q->qh) {
		nfq_destroy_queue(nfq_q->qh);
	}

	/*im here in the list and running thread*/
	objlock(nfqueues);
	if (objcnt(nfq_q->nfq) <= 3) {
		setflag(nfq_q->nfq, NFQUEUE_DONE);
		remove_bucket_item(nfqueues->queues, nfq_q->nfq);
	}
	objunlock(nfqueues);
	objunref(nfq_q->nfq);
}

static void *nfqueue_thread(void **data) {
	struct nfq_struct *nfq = *data;
	fd_set  rd_set, act_set;
	struct timeval tv;
	int len, selfd;
	char buf[4096];
	int opt = 1;

	FD_ZERO(&rd_set);
	FD_SET(nfq->fd, &rd_set);
	fcntl(nfq->fd, F_SETFD, O_NONBLOCK);
	ioctl(nfq->fd, FIONBIO, &opt);

	while (!testflag(nfq, NFQUEUE_DONE) && framework_threadok(data)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(nfq->fd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else
			if (selfd < 0) {
				break;
			}

		if ((FD_ISSET(nfq->fd, &act_set)) &&
				((len = recv(nfq->fd, buf, sizeof(buf), 0)) >= 0)) {
			objlock(nfq);
			nfq_handle_packet(nfq->h, buf, len);
			objunlock(nfq);
		}
	}

	return (NULL);
}

static struct nfq_struct *nfqueue_init(uint16_t pf) {
	struct nfq_struct *nfq;

	if (!(nfq = objalloc(sizeof(*nfq), nfqueue_close))) {
		return (NULL);
	}
	nfq->pf = pf;

	if (!(nfq->h = nfq_open())) {
		objunref(nfq);
		return (NULL);
	}

	if (nfq_unbind_pf(nfq->h, pf)) {
		objunref(nfq);
		return (NULL);
	}

	if (nfq_bind_pf(nfq->h, pf)) {
		objunref(nfq);
		return (NULL);
	}

	if ((nfq->fd = nfq_fd(nfq->h)) < 0) {
		objunref(nfq);
		return (NULL);
	}

	if (nfqueues) {
		objref(nfqueues);
	} else
		if (!(nfqueues = objalloc(sizeof(*nfqueues), nfqueues_close))) {
			objunref(nfq);
			return (NULL);
		}

	objlock(nfqueues);
	if ((nfqueues->queues || (nfqueues->queues = create_bucketlist(0, nfqueue_hash))) &&
			!addtobucket(nfqueues->queues, nfq)) {
		objunref(nfqueues);
		objunref(nfq);
		return (NULL);
	}
	objunlock(nfqueues);

	framework_mkthread(nfqueue_thread, NULL, NULL, nfq);

	return (nfq);
}

static int nfqueue_callback(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *nfad, void *data) {
	struct nfq_queue *nfq_q = data;
	unsigned char *pkt;
	struct nfqnl_msg_packet_hdr *ph;
	void *mangle = NULL;
	uint32_t ret, mark;
	uint32_t id = 0;
	uint32_t len = 0;
	uint32_t verdict = NF_DROP;

	if ((ph = nfq_get_msg_packet_hdr(nfad))) {
		id = ntohl(ph->packet_id);
	}
	mark = nfq_get_nfmark(nfad);

	if ((len = nfq_get_payload(nfad, &pkt)) <= 0) {
		pkt = NULL;
	}

	if (nfq_q->cb) {
		verdict = nfq_q->cb(nfad, ph, (char *)pkt, len, nfq_q->data, &mark, &mangle);
	}

	if (mangle && !(len = objsize(mangle))) {
		objunref(mangle);
		mangle = NULL;
	}

	ret = nfq_set_verdict2(qh, id, verdict, mark, len, (mangle) ? mangle : pkt);
	if (mangle) {
		objunref(mangle);
	}

	return (ret);
}

extern struct nfq_queue *nfqueue_attach(uint16_t pf, uint16_t num, uint8_t mode, uint32_t range, nfqueue_cb cb, void *data) {
	struct nfq_queue *nfq_q;

	if (!(nfq_q = objalloc(sizeof(*nfq_q), nfqueue_close_q))) {
		return (NULL);
	}

	objlock(nfqueues);
	if (!(nfqueues && (nfq_q->nfq = bucket_list_find_key(nfqueues->queues, &pf))) &&
			!(nfq_q->nfq || (nfq_q->nfq = nfqueue_init(pf)))) {
		objunlock(nfqueues);
		objunref(nfq_q);
		return (NULL);
	}
	objunlock(nfqueues);

	if (!(nfq_q->qh = nfq_create_queue(nfq_q->nfq->h, num, &nfqueue_callback, nfq_q))) {
		objunref(nfq_q);
		return (NULL);
	}

	if (cb) {
		nfq_q->cb = cb;
	}

	if (data) {
		nfq_q->data = data;
	}

	nfq_set_mode(nfq_q->qh, mode, range);

	return (nfq_q);
}

extern uint16_t snprintf_pkt(struct nfq_data *tb, struct nfqnl_msg_packet_hdr *ph, uint8_t *pkt, char *buff, uint16_t len) {
	struct iphdr *ip = (struct iphdr *)pkt;
	char *tmp = buff;
	uint32_t id, mark, ifi;
	uint16_t tlen, left = len;
	char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];

	if (ph) {
		id = ntohl(ph->packet_id);
		snprintf(tmp, left, "hw_protocol=0x%04x hook=%u id=%u ",
				 ntohs(ph->hw_protocol), ph->hook, id);
		tlen = strlen(tmp);
		tmp += tlen;
		left -= tlen;
	}

	if ((mark = nfq_get_nfmark(tb))) {
		snprintf(tmp, left, "mark=%u ", mark);
		tlen = strlen(tmp);
		tmp += tlen;
		left -= tlen;
	}

	if ((ifi = nfq_get_indev(tb))) {
		snprintf(tmp, left, "indev=%u ", ifi);
		tlen = strlen(tmp);
		tmp += tlen;
		left -= tlen;
	}

	if ((ifi = nfq_get_outdev(tb))) {
		snprintf(tmp, left, "outdev=%u ", ifi);
		tlen = strlen(tmp);
		tmp += tlen;
		left -= tlen;
	}

	if (pkt && (ip->version == 4)) {
		union l4hdr *l4 = (union l4hdr *)(pkt + (ip->ihl*4));

		inet_ntop(AF_INET, &ip->saddr, saddr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip->daddr, daddr, INET_ADDRSTRLEN);

		snprintf(tmp, left, "src=%s dst=%s proto=%i ", saddr, daddr, ip->protocol);
		tlen = strlen(tmp);
		tmp += tlen;
		left -= tlen;

		switch(ip->protocol) {
			case IPPROTO_TCP:
				snprintf(tmp, left, "sport=%i dport=%i ", ntohs(l4->tcp.source), ntohs(l4->tcp.dest));
				break;
			case IPPROTO_UDP:
				snprintf(tmp, left, "sport=%i dport=%i ", ntohs(l4->udp.source), ntohs(l4->udp.dest));
				break;
			case IPPROTO_ICMP:
				snprintf(tmp, left, "type=%i code=%i id=%i ", l4->icmp.type, l4->icmp.code, ntohs(l4->icmp.un.echo.id));
				break;
		}
		tlen = strlen(tmp);
		tmp += tlen;
		left -= tlen;
	}

	return (len - left);
}

/** @}*/
