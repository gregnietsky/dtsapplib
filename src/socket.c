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

/** @defgroup LIB-Sock Network socket interface
  * @ingroup LIB
  * @brief Allocate and initialise a socket for use as a client or server.
  *
  * 
  * @addtogroup LIB-Sock
  * @{
  * @file
  * @brief Allocate and initialise a socket for use as a client or server.
  *
  * This is part of the socket interface to upport encrypted sockets
  * a ssldata refernece will be created and passed on socket initialization.
  *
  * @see @ref LIB-Sock-SSL*/

#ifndef __WIN32__
#include <netdb.h>
#endif
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "include/dtsapp.h"
#include "include/private.h"

/* socket handling thread*/
struct socket_handler {
	struct fwsocket *sock;
	void *data;
	socketrecv	client;
	threadcleanup	cleanup;
	socketrecv	connect;
};

static int hash_socket(const void *data, int key) {
	int ret;
	const struct fwsocket *sock = data;
	const int *hashkey = (key) ? data : &sock->sock;

	ret = *hashkey;

	return (ret);
}

extern void close_socket(struct fwsocket *sock) {
	if (sock) {
		setflag(sock, SOCK_FLAG_CLOSE);
		objunref(sock);
	}
}

static void clean_fwsocket(void *data) {
	struct fwsocket *sock = data;

	if (sock->ssl) {
		objunref(sock->ssl);
	}

	/*im closing remove from parent list*/
	if (sock->parent) {
		if (sock->parent->children) {
			remove_bucket_item(sock->parent->children, sock);
		}
		objunref(sock->parent);
	}

	/*looks like the server is shut down*/
	if (sock->children) {
		objunref(sock->children);
	}

	if (sock->sock >= 0) {
		close(sock->sock);
	}
}

extern struct fwsocket *make_socket(int family, int type, int proto, void *ssl) {
	struct fwsocket *si;

	if (!(si = objalloc(sizeof(*si),clean_fwsocket))) {
		return NULL;
	}

	if ((si->sock = socket(family, type, proto)) < 0) {
		objunref(si);
		return NULL;
	};

	if (ssl) {
		si->ssl = ssl;
	}
	si->type = type;
	si->proto = proto;

	return (si);
}

static struct fwsocket *accept_socket(struct fwsocket *sock) {
	struct fwsocket *si;
	socklen_t salen = sizeof(si->addr);

	if (!(si = objalloc(sizeof(*si),clean_fwsocket))) {
		return NULL;
	}

	objlock(sock);
	if ((si->sock = accept(sock->sock, &si->addr.sa, &salen)) < 0) {
		objunlock(sock);
		objunref(si);
		return NULL;
	}

	si->type = sock->type;
	si->proto = sock->proto;

	if (sock->ssl) {
		tlsaccept(si, sock->ssl);
	}
	objunlock(sock);

	return (si);
}

static struct fwsocket *_opensocket(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int ctype, int backlog) {
	struct	addrinfo hint, *result, *rp;
	struct fwsocket *sock = NULL;
	socklen_t salen = sizeof(union sockstruct);
#ifndef __WIN32__
	int on = 1;
#endif

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = family;
	hint.ai_socktype = stype;
	hint.ai_protocol = proto;

	if (getaddrinfo(ipaddr, port, &hint, &result) || !result) {
		return (NULL);
	}

	for(rp = result; rp; rp = result->ai_next) {
		if (!(sock = make_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol, ssl))) {
			continue;
		}
		if ((!ctype && !connect(sock->sock, rp->ai_addr, rp->ai_addrlen)) ||
				(ctype && !bind(sock->sock, rp->ai_addr, rp->ai_addrlen))) {
			break;
		}
		objunref(sock);
		sock = NULL;
	}

	if (!sock || !rp) {
		if (sock) {
			objunref(sock);
		}
		freeaddrinfo(result);

		return (NULL);
	}

	if (ctype) {
		sock->flags |= SOCK_FLAG_BIND;
		memcpy(&sock->addr.ss, rp->ai_addr, sizeof(sock->addr.ss));
#ifndef __WIN32__
		setsockopt(sock->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
		setsockopt(sock->sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
#endif
		switch(sock->type) {
			case SOCK_STREAM:
			case SOCK_SEQPACKET:
				listen(sock->sock, backlog);
				/* no break */
			default
					:
				break;
		}
	} else {
		getsockname(sock->sock, &sock->addr.sa, &salen);
	}

	freeaddrinfo(result);
	return (sock);
}

extern struct fwsocket *sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl) {
	return(_opensocket(family, stype, proto, ipaddr, port, ssl, 0, 0));
}

extern struct fwsocket *udpconnect(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, ssl, 0, 0));
}

extern struct fwsocket *tcpconnect(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, ssl, 0, 0));
}

extern struct fwsocket *sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int backlog) {
	return(_opensocket(family, stype, proto, ipaddr, port, ssl, 1, backlog));
}

extern struct fwsocket *udpbind(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, ssl, 1, 0));
}

extern struct fwsocket *tcpbind(const char *ipaddr, const char *port, void *ssl, int backlog) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, ssl, 1, backlog));
}

static void _socket_handler_clean(void *data) {
	struct socket_handler *fwsel = data;

	/*call cleanup and remove refs to data*/
	if (fwsel->cleanup) {
		fwsel->cleanup(fwsel->data);
	}
	if (fwsel->data) {
		objunref(fwsel->data);
	}
}

static void *_socket_handler(void **data) {
	struct socket_handler *sockh = *data;
	struct fwsocket *sock = sockh->sock;
	struct fwsocket *newsock;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd, sockfd, type, flags;
	struct bucket_loop *bloop;

	objlock(sock);
	FD_ZERO(&rd_set);
	sockfd = sock->sock;
	type = sock->type;
	if ((sock->flags & SOCK_FLAG_BIND) && (sock->ssl || !(sock->type == SOCK_DGRAM))) {
		flags = (SOCK_FLAG_BIND & sock->flags);
	} else {
		flags = 0;
	}
	FD_SET(sockfd, &rd_set);
	objunlock(sock);

	while (framework_threadok(data) && !testflag(sock, SOCK_FLAG_CLOSE)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(sockfd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			if ((type == SOCK_DGRAM) && (flags & SOCK_FLAG_BIND)) {
				dtlshandltimeout(sock);
			}
			continue;
		} else
			if (selfd < 0) {
				break;
			}

		if (FD_ISSET(sockfd, &act_set)) {
			if (flags & SOCK_FLAG_BIND) {
				switch (type) {
					case SOCK_STREAM:
					case SOCK_SEQPACKET:
						newsock = accept_socket(sock);
						break;
					case SOCK_DGRAM:
						newsock = dtls_listenssl(sock);
						break;
					default
							:
						newsock = NULL;
						break;
				}
				if (newsock) {
					objref(sock);
					newsock->parent = sock;
					addtobucket(sock->children, newsock);
					socketclient(newsock, sockh->data, sockh->client, NULL);
					if (sockh->connect) {
						sockh->connect(newsock, sockh->data);
					}
					objunref(newsock); /*pass ref to thread*/
				}
			} else {
				sockh->client(sockh->sock, sockh->data);
			}
		}
	}

	if (sock->ssl) {
		ssl_shutdown(sock->ssl, sock->sock);
	}

	/*close children*/
	if (sock->children) {
		bloop = init_bucket_loop(sock->children);
		while(bloop && (newsock = next_bucket_loop(bloop))) {
			remove_bucket_loop(bloop);
			objlock(newsock);
			if (newsock->parent) {
				objunref(newsock->parent);
				newsock->parent = NULL;
			}
			objunlock(newsock);
			close_socket(newsock); /*remove ref*/
		}
		stop_bucket_loop(bloop);
	}

	objunref(sock);

	return NULL;
}

static void _start_socket_handler(struct fwsocket *sock, socketrecv read,
								  socketrecv acceptfunc, threadcleanup cleanup, void *data) {
	struct socket_handler *sockh;

	if (!sock || !read || !(sockh = objalloc(sizeof(*sockh), NULL))) {
		return;
	}

	sockh->sock = sock;
	sockh->client = read;
	sockh->cleanup = cleanup;
	sockh->connect = acceptfunc;
	sockh->data = data;

	/* grab ref for data and pass sockh*/
	objref(data);
	objref(sock);
	framework_mkthread(_socket_handler, _socket_handler_clean, NULL, sockh);
	objunref(sockh);
}

extern void socketserver(struct fwsocket *sock, socketrecv read,
						 socketrecv acceptfunc, threadcleanup cleanup, void *data) {

	objlock(sock);
	if (sock->flags & SOCK_FLAG_BIND) {
		if (sock->ssl || !(sock->type == SOCK_DGRAM)) {
			sock->children = create_bucketlist(6, hash_socket);
		}
		if (sock->ssl && (sock->type == SOCK_DGRAM)) {
			objunlock(sock);
			dtsl_serveropts(sock);
		} else {
			objunlock(sock);
		}
	} else {
		objunlock(sock);
	}
	_start_socket_handler(sock, read, acceptfunc, cleanup, data);
}

extern void socketclient(struct fwsocket *sock, void *data, socketrecv read, threadcleanup cleanup) {
	startsslclient(sock);

	_start_socket_handler(sock, read, NULL, cleanup, data);
}
