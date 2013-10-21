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

/** @addtogroup LIB-Sock
  * @{
  *
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
#include <stdlib.h>

#include "include/dtsapp.h"
#include "include/private.h"

/** @brief Socket handling thread data.*/
struct socket_handler {
	/** @brief Socket this thread manages.*/
	struct fwsocket *sock;
	/** @brief Reference to data passed in callbacks*/
	void *data;
	/** @brief Callback called when the socket is ready to read*/
	socketrecv	client;
	/** @brief Callback to call when the thread closes to allow
	  * additional cleanup*/
	threadcleanup	cleanup;
	/** @brief If a client connects to a bound port this callback is
	  * called on connect*/
	socketrecv	connect;
};

static int32_t hash_socket(const void *data, int key) {
	int ret;
	const struct fwsocket *sock = data;
	const int *hashkey = (key) ? data : &sock->sock;

	ret = *hashkey;

	return (ret);
}

/** @brief Mark the socket for closure and release the reference.
  *
  * @param sock Socket to close.*/
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

/** @brief Allocate a socket structure and return reference.
  *
  * The socket FD is assined by a call to socket.
  * @warning This function should not be called directly.
  * @param family Protocol family.
  * @param type Socket type.
  * @param proto Protocol to be used.
  * @param ssl SSL structure to associate with the socket.
  * @returns Reference to socket structure holding a FD.*/
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

/** @brief Create and return a socket structure from accept()
  * @param sock Reference to the socket its accepted on.
  * @return Reference to new socket.*/
extern struct fwsocket *accept_socket(struct fwsocket *sock) {
	struct fwsocket *si;
	socklen_t salen = sizeof(si->addr);
#ifdef __WIN32
/*	unsigned long on = 1;*/
#endif

	if (!(si = objalloc(sizeof(*si),clean_fwsocket))) {
		return NULL;
	}

	objlock(sock);
	if ((si->sock = accept(sock->sock, &si->addr.sa, &salen)) < 0) {
		objunlock(sock);
		objunref(si);
		return NULL;
	}

#ifdef __WIN32
/*	ioctlsocket(si->sock, FIONBIO, (unsigned long*)&on);*/
#endif

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
		if (ctype) {
#ifndef __WIN32__
			setsockopt(sock->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
			setsockopt(sock->sock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
#else
/*		ioctlsocket(sock->sock, SO_REUSEADDR, (unsigned long*)&on);*/
#endif
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
#ifdef __WIN32
/*		ioctlsocket(sock->sock, FIONBIO, (unsigned long*)&on);*/
#endif
		sock->flags |= SOCK_FLAG_BIND;
		memcpy(&sock->addr.ss, rp->ai_addr, sizeof(sock->addr.ss));
		switch(sock->type) {
			case SOCK_STREAM:
			case SOCK_SEQPACKET:
				listen(sock->sock, backlog);
				/* no break */
			default:
				break;
		}
	} else {
		getsockname(sock->sock, &sock->addr.sa, &salen);
	}

	freeaddrinfo(result);
	return (sock);
}

/** @brief Generic client socket.
  *
  * @see udpconnect
  * @see tcpconnect
  * @param family Protocol family.
  * @param stype Socket type.
  * @param proto Socket protocol.
  * @param ipaddr Ipaddr to connect too.
  * @param port Port to connect too.
  * @param ssl SSL structure to associate with socket.
  * @returns Reference to socket structure.*/
extern struct fwsocket *sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl) {
	return(_opensocket(family, stype, proto, ipaddr, port, ssl, 0, 0));
}

/** @brief UDP Socket client.
  *
  * @see sockconnect
  * @see tcpconnect
  * @param ipaddr Ipaddr to connect too.
  * @param port Port to connect too.
  * @param ssl SSL structure to associate with socket.
  * @returns Reference to socket structure.*/
extern struct fwsocket *udpconnect(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, ssl, 0, 0));
}

/** @brief TCP Socket client.
  *
  * @see sockconnect
  * @see udpconnect
  * @param ipaddr Ipaddr to connect too.
  * @param port Port to connect too.
  * @param ssl SSL structure to associate with socket.
  * @returns Reference to socket structure.*/
extern struct fwsocket *tcpconnect(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, ipaddr, port, ssl, 0, 0));
}

/** @brief Generic server socket.
  *
  * @see udpbind
  * @see tcpbind
  * @param family Protocol family.
  * @param stype Socket type.
  * @param proto Socket protocol.
  * @param ipaddr Ipaddr to connect too.
  * @param port Port to connect too.
  * @param ssl SSL structure to associate with socket.
  * @param backlog Connection backlog passed to listen.
  * @returns Reference to socket structure.*/
extern struct fwsocket *sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int backlog) {
	return(_opensocket(family, stype, proto, ipaddr, port, ssl, 1, backlog));
}

/** @brief UDP server socket.
  *
  * @see sockbind
  * @see tcpbind
  * @param ipaddr Ipaddr to connect too.
  * @param port Port to connect too.
  * @param ssl SSL structure to associate with socket.
  * @returns Reference to socket structure.*/
extern struct fwsocket *udpbind(const char *ipaddr, const char *port, void *ssl) {
	return (_opensocket(PF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipaddr, port, ssl, 1, 0));
}

/** @brief Generic server socket.
  *
  * @see udpbind
  * @see sockbind
  * @param ipaddr Ipaddr to connect too.
  * @param port Port to connect too.
  * @param ssl SSL structure to associate with socket.
  * @param backlog Connection backlog passed to listen.
  * @returns Reference to socket structure.*/
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

static void *_socket_handler(void *data) {
	struct socket_handler *sockh = data;
	struct fwsocket *sock = sockh->sock;
	struct fwsocket *newsock;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd, sockfd, type, flags;
	struct bucket_loop *bloop;
#ifdef __WIN32
	int errcode;
#endif
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

	while (framework_threadok() && !testflag(sock, SOCK_FLAG_CLOSE)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(sockfd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
#ifndef __WIN32
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
#else
		errcode = WSAGetLastError();
		if (((selfd == SOCKET_ERROR) && (errcode == WSAEINTR)) || (!selfd)) {
#endif
			if ((type == SOCK_DGRAM) && (flags & SOCK_FLAG_BIND)) {
				dtlshandltimeout(sock);
			}
			continue;
		} else if (selfd < 0) {
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
					default:
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
		objunref(bloop);
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
	framework_mkthread(_socket_handler, _socket_handler_clean, NULL, sockh, 0);
	objunref(sockh);
}

/** @brief Create a server thread with a socket that has been created with
  * sockbind udpbind or tcpbind.
  *
  * @see sockclient
  * @see threadcleanup
  * @see socketrecv
  * @param sock Reference to a bound socket.
  * @param read Callback to handle data when ready to read.
  * @param acceptfunc Function to call on connection accept.
  * @param cleanup Thread cleanup function for when the socket closes.
  * @param data to send to the callbacks in paramaters.*/
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

/** @brief Create a server thread with a socket that has been created with
  * sockbind udpbind or tcpbind.
  *
  * @see sockclient
  * @see threadcleanup
  * @see socketrecv
  * @param sock Reference to a bound socket.
  * @param data to send to the callbacks in paramaters.
  * @param read Callback to handle data when ready to read.
  * @param cleanup Thread cleanup function for when the socket closes.*/
extern void socketclient(struct fwsocket *sock, void *data, socketrecv read, threadcleanup cleanup) {
	startsslclient(sock);

	_start_socket_handler(sock, read, NULL, cleanup, data);
}

/** @brief Create a multicast socket.
  *
  * A multicast socket is both a client and server due to the nature of multicasting
  * writing to a multicast socket should only be done with socketwrite not socketwrite_d
  * the socket is created on a interface and the initial address can be set.
  * @todo Win32 support for inet_ntop/inet_pton
  * @param iface Interface to send and recieve multicast traffic.
  * @param family IP address family PF_INET or PF_INET6.
  * @param mcastip Multicast ip to use must be in "family".
  * @param port Port to use.
  * @param flags Multicast flags currently disables LOOP.
  * @returns Reference to multicast ocket structure.*/
#ifndef __WIN32
struct fwsocket *mcast_socket(const char *iface, int family, const char *mcastip, const char *port, int flags) {
	const char *srcip;
#else
struct fwsocket *mcast_socket(const char *ipaddr, int family, const char *mcastip, const char *port, int flags) {
#endif
	struct fwsocket *fws;
	struct  addrinfo hint, *result, *rp;
	struct in_addr *srcif;
	int on = 1;
	int off = 0;
	int ttl = 50;
	socklen_t slen = sizeof(union sockstruct);

#ifdef __WIN32
	/* No support for win32 lacking inet_pton / inet_ntop*/
	if (family == PF_INET6) {
		return NULL;
	}
#endif

        memset(&hint, 0, sizeof(hint));
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;
	hint.ai_protocol = IPPROTO_UDP;

#ifndef __WIN32
	if (!(srcip = get_ifipaddr(iface, family))) {
                return NULL;
	}

        if (getaddrinfo(srcip, port, &hint, &result) || !result) {
		free((void*)srcip);
                return NULL;
        }
	free((void*)srcip);
#else
        if (getaddrinfo(ipaddr, port, &hint, &result) || !result) {
                return NULL;
        }
#endif

	for(rp = result; rp; rp = result->ai_next) {
		if (!(fws = make_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol, NULL))) {
			continue;
		}
		break;
	}

	if (!rp || !fws) {
		freeaddrinfo(result);
		return NULL;
	}

	if(setsockopt(fws->sock, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on))) {
		objunref(fws);
		freeaddrinfo(result);
		return NULL;
	}

	if (rp->ai_family == PF_INET) {
		struct in_addr mcastip4;
		struct ip_mreq mg;
		struct sockaddr_in *src_ip;

		src_ip = (struct sockaddr_in*)rp->ai_addr;

		if (setsockopt(fws->sock, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl))) {
			objunref(fws);
			freeaddrinfo(result);
			return NULL;
		}

		if (flags && setsockopt(fws->sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&off, sizeof(off))) {
			freeaddrinfo(result);
			objunref(fws);
			return NULL;
		}

		if (mcastip) {
			mcastip4.s_addr = inet_addr(mcastip);
		} else {
			seedrand();
			mcast4_ip(&mcastip4);
		}

		mg.imr_multiaddr = mcastip4;
		mg.imr_interface.s_addr = src_ip->sin_addr.s_addr;
		if (setsockopt(fws->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mg, sizeof(mg))) {
			objunref(fws);
			freeaddrinfo(rp);
			return NULL;
		}

		memset(&srcif, 0, sizeof(srcif));
		srcif = &src_ip->sin_addr;
		if(setsockopt(fws->sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)srcif, sizeof(*srcif))) {
			freeaddrinfo(rp);
			objunref(fws);
			return NULL;
		}
		src_ip->sin_addr.s_addr = mcastip4.s_addr;
#ifndef __WIN32
	} else if (rp->ai_family == PF_INET6) {
		struct in6_addr mcastip6;
		struct ipv6_mreq mg;
		struct sockaddr_in6 *src_ip;
		int ifidx;

		ifidx = get_iface_index(iface);
		src_ip = (struct sockaddr_in6*)rp->ai_addr;

		if (setsockopt(fws->sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*)&ttl, sizeof(ttl))) {
			objunref(fws);
			freeaddrinfo(result);
			return NULL;
		}

		if (flags && setsockopt(fws->sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char*)&off, sizeof(off))) {
			freeaddrinfo(result);
			objunref(fws);
			return NULL;
		}

		if (mcastip) {
			inet_pton(PF_INET6, mcastip, &mcastip6);
			/*NO WIN32 IPv6 Support*/
		} else {
			seedrand();
			mcast6_ip(&mcastip6);
		}

		mg.ipv6mr_multiaddr = mcastip6;
		mg.ipv6mr_interface = ifidx;
		if (setsockopt(fws->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char*)&mg, sizeof(mg))) {
			objunref(fws);
			freeaddrinfo(rp);
			return NULL;
		}

		if (setsockopt(fws->sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char*)&ifidx, sizeof(ifidx))) {
			objref(fws);
			freeaddrinfo(rp);
			return NULL;
		}

		src_ip->sin6_addr = mcastip6;
#endif
	}

	if (bind(fws->sock, (struct sockaddr*)rp->ai_addr, sizeof(struct sockaddr_storage))) {
		freeaddrinfo(result);
		objunref(fws);
		return NULL;
	}

	getsockname(fws->sock, &fws->addr.sa, &slen);
	freeaddrinfo(result);
	fws->flags |= SOCK_FLAG_MCAST;

	return fws;
}

const char *sockaddr2ip(union sockstruct *addr, char *buff, int blen) {
#ifdef __WIN32
	uint32_t ip_addr4;
	uint8_t	*ip4addr;
#endif

	if (!buff) {
		return NULL;
	}

	switch (addr->ss.ss_family) {
		case PF_INET:
#ifndef __WIN32
			inet_ntop(PF_INET, &addr->sa4.sin_addr, buff, blen);
#else
			ip_addr4 = ntohl(addr->sa4.sin_addr.s_addr);
			ip4addr = (uint8_t*)&ip_addr4;
			snprintf(buff, blen, "%i.%i.%i.%i", ip4addr[0], ip4addr[1], ip4addr[2], ip4addr[3]);
#endif
			break;
		case PF_INET6:
#ifndef __WIN32
			inet_ntop(PF_INET6, &addr->sa6.sin6_addr, buff, blen);
#else
			return NULL;
#endif
			break;
	}
	return buff;
}

/** @}*/

