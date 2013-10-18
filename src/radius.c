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
  * @brief Simple radius client implementation.
  * @ingroup LIB-RADIUS
  * @addtogroup LIB-RADIUS
@verbatim
 * User password crypt function from the freeradius project (addattrpasswd)
 * Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 The FreeRADIUS Server Project
@endverbatim
  * @{*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#ifdef __WIN32__
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <uuid/uuid.h>
#include <openssl/md5.h>
#include "include/dtsapp.h"

/** @brief Radius Packet*/
struct radius_packet {
	/** @brief Radius packet code
	  * @see RADIUS_CODE.*/
	unsigned char code;
	/** @brief Packet ID.*/
	unsigned char id;
	/** @brief Packet length.*/
	unsigned short len;
	/** @brief Authentification token.*/
	unsigned char token[RAD_AUTH_TOKEN_LEN];
	/** @brief Radius Attributes.*/
	unsigned char attrs[RAD_AUTH_PACKET_LEN - RAD_AUTH_HDR_LEN];
};

/** @brief Radius session.
  *
  * A radius session is based on a ID packet for
  * session stored till a response the request token is also stored*/
struct radius_session {
	/** @brief Session id.*/
	unsigned short id;
	/** @brief Radius request auth token.*/
	unsigned char request[RAD_AUTH_TOKEN_LEN];
	/** @brief Callback data passed to callback.*/
	void	*cb_data;
	/** @brief Radius callback.*/
	radius_cb read_cb;
	/** @brief Original length of packet.*/
	unsigned int olen;
	/** @brief Radius packet.*/
	struct radius_packet *packet;
	/** @brief Time packet was sent.*/
	struct timeval sent;
	/** @brief Password requires special handling.*/
	const char *passwd;
	/** @brief Retries available.*/
	char	retries;
	/** @brief Minimum id of server to use.*/
	char	minserver;
};

/** @brief Radius connection.
  *
  * connect to the server one connection holds 256 sessions*/
struct radius_connection {
	/** @brief Reference to socket.*/
	struct fwsocket *socket;
	/** @brief Connection ID.*/
	unsigned char id;
	/** @brief Reference to radius server.*/
	struct radius_server *server;
	/** @brief Bucket list of sessions.*/
	struct bucket_list *sessions;
};

/** @brief Radius Server
  *
  * define a server with host auth/acct port and secret
  * create "connextions" on demand each with upto 256 sessions
  * servers should not be removed without removing all and reloading*/
struct radius_server {
	/** @brief Server name.*/
	const char	*name;
	/** @brief Server authport.*/
	const char	*authport;
	/** @brief Server accounting port.*/
	const char	*acctport;
	/** @brief Server secret.*/
	const char	*secret;
	/** @brief Server hash based on server count.*/
	unsigned char	id;
	/** @brief Server timeout.*/
	int		timeout;
	/** @brief Server out of service time.*/
	struct timeval	service;
	/** @brief Bucket list of connextions.*/
	struct bucket_list *connex;
};

static struct bucket_list *servers = NULL;

static struct radius_connection *radconnect(struct radius_server *server);

static unsigned char *addradattr(struct radius_packet *packet, char type, unsigned char *val, char len) {
	unsigned char *data = packet->attrs + packet->len - RAD_AUTH_HDR_LEN;

	if (!len) {
		return NULL;
	}

	data[0] = type;
	data[1] = len + 2;
	if (val) {
		memcpy(data + 2, val, len);
	}

	packet->len += data[1];
	return (data);
}

/** @brief Add a integer attribute too the packet.
  * @param packet Radius packet to add too.
  * @param type Attribute been added.
  * @param val Value to add.*/
extern void addradattrint(struct radius_packet *packet, char type, unsigned int val) {
	unsigned int tval;

	tval = htonl(val);
	addradattr(packet, type, (unsigned char *)&tval, sizeof(tval));
}

/** @brief Add a integer attribute too the packet.
  * @param packet Radius packet to add too.
  * @param type Attribute been added.
  * @param ipaddr IP to add.*/
extern void addradattrip(struct radius_packet *packet, char type, char *ipaddr) {
	unsigned int tval;

	tval = inet_addr(ipaddr);
	addradattr(packet, type, (unsigned char *)&tval, sizeof(tval));
}

/** @brief Add a integer attribute too the packet.
  * @param packet Radius packet to add too.
  * @param type Attribute been added.
  * @param str Value to add.*/
extern void addradattrstr(struct radius_packet *packet, char type, char *str) {
	addradattr(packet, type, (unsigned char *)str, strlen(str));
}

static void addradattrpasswd(struct radius_packet *packet, const char *pw, const char *secret) {
	unsigned char pwbuff[RAD_MAX_PASS_LEN];
	unsigned char digest[RAD_AUTH_TOKEN_LEN];
	MD5_CTX c, old;
	int len, n, i;

	len = strlen(pw);
	if (len > RAD_MAX_PASS_LEN) {
		len = RAD_MAX_PASS_LEN;
	}

	memcpy(pwbuff, pw, len);
	memset(pwbuff+len, 0, RAD_MAX_PASS_LEN -len);

	/* pad len to RAD_AUTH_TOKEN_LEN*/
	if (!len) {
		len = RAD_AUTH_TOKEN_LEN;
	}  else
		if (!(len & 0xf)) {
			len += 0xf;
			len &= ~0xf;
		}

	MD5_Init(&c);
	MD5_Update(&c, secret, strlen(secret));
	old = c;

	MD5_Update(&c, packet->token, RAD_AUTH_TOKEN_LEN);
	for (n = 0; n < len; n += RAD_AUTH_TOKEN_LEN) {
		if (n > 0) {
			c = old;
			MD5_Update(&c, pwbuff + n - RAD_AUTH_TOKEN_LEN, RAD_AUTH_TOKEN_LEN);
		}
		MD5_Final(digest, &c);
		for (i = 0; i < RAD_AUTH_TOKEN_LEN; i++) {
			pwbuff[i + n] ^= digest[i];
		}
	}
	addradattr(packet, RAD_ATTR_USER_PASSWORD, pwbuff, len);
}

/** @brief Create a new radius packet.
  *
  * @see RADIUS_CODE
  * @param code Radius packet  type.
  * @returns reference to new radius packet of specified type.*/
extern struct radius_packet *new_radpacket(unsigned char code) {
	struct radius_packet *packet;

	if ((packet = malloc(sizeof(*packet)))) {
		memset(packet, 0, sizeof(*packet));
		packet->len = RAD_AUTH_HDR_LEN;
		packet->code = code;
		genrand(&packet->token, RAD_AUTH_TOKEN_LEN);
	}
	return (packet);
}

static int32_t hash_session(const void *data, int key) {
	unsigned int ret;
	const struct radius_session *session = data;
	const unsigned char *hashkey = (key) ? data : &session->id;

	ret = *hashkey << 24;

	return (ret);
}

static int32_t hash_connex(const void *data, int key) {
	int ret;
	const struct radius_connection *connex = data;
	const int *hashkey = (key) ? data : &connex->socket;

	ret = *hashkey;

	return (ret);
}

static int32_t hash_server(const void *data, int key) {
	int ret;
	const struct radius_server *server = data;
	const unsigned char *hashkey = (key) ? data : &server->id;

	ret = *hashkey;

	return(ret);
}

static void del_radserver(void *data) {
	struct radius_server *server = data;

	if (server->name) {
		free((char *)server->name);
	}
	if (server->authport) {
		free((char *)server->authport);
	}
	if (server->acctport) {
		free((char *)server->acctport);
	}
	if (server->secret) {
		free((char *)server->secret);
	}
	if (server->connex) {
		objunref(server->connex);
	}
}

/** @brief Add new radius server to list of servers.
  * @param ipaddr IP address or hostname of server.
  * @param auth Athentification port.
  * @param acct Accounting port.
  * @param secret Shared secret.
  * @param timeout Time to take offline on failure.*/
extern void add_radserver(const char *ipaddr, const char *auth, const char *acct, const char *secret, int timeout) {
	struct radius_server *server;

	if ((server = objalloc(sizeof(*server), del_radserver))) {
		ALLOC_CONST(server->name, ipaddr);
		ALLOC_CONST(server->authport, auth);
		ALLOC_CONST(server->acctport, acct);
		ALLOC_CONST(server->secret, secret);
		if (!servers) {
			servers = create_bucketlist(0, hash_server);
		}
		server->id = bucket_list_cnt(servers);
		server->timeout = timeout;
		gettimeofday(&server->service, NULL);
		addtobucket(servers, server);
	}

	objunref(server);
}

static void del_radsession(void *data) {
	struct radius_session *session = data;

	if (session->passwd) {
		free((void *)session->passwd);
	}
	if (session->packet) {
		free(session->packet);
	}
}

static struct radius_session *rad_session(struct radius_packet *packet, struct radius_connection *connex,
		const char *passwd, radius_cb read_cb, void *cb_data) {
	struct radius_session *session = NULL;

	if ((session = objalloc(sizeof(*session), del_radsession))) {
		if (!connex->sessions) {
			connex->sessions = create_bucketlist(4, hash_session);
		}
		memcpy(session->request, packet->token, RAD_AUTH_TOKEN_LEN);
		session->id = packet->id;
		session->packet = packet;
		session->read_cb = read_cb;
		session->cb_data = cb_data;
		session->olen = packet->len;
		session->retries = 2;
		ALLOC_CONST(session->passwd, passwd);
		addtobucket(connex->sessions, session);
	}
	return (session);
}

static int _send_radpacket(struct radius_packet *packet, const char *userpass, struct radius_session *hint,
						   radius_cb read_cb, void *cb_data) {
	int scnt;
	unsigned char *vector;
	unsigned short len;
	struct radius_server *server;
	struct radius_session *session;
	struct radius_connection *connex;
	struct bucket_loop *sloop, *cloop;
	struct timeval	curtime;


	gettimeofday(&curtime, NULL);
	sloop = init_bucket_loop(servers);
	objref(hint);
	while (sloop && (server = next_bucket_loop(sloop))) {
		objlock(server);
		if ((hint && (server->id <= hint->minserver)) ||
				(server->service.tv_sec > curtime.tv_sec)) {
			objunlock(server);
			objunref(server);
			continue;
		}
		if (!server->connex) {
			connex = radconnect(server);
			objunref(connex);
			objunlock(server);
			objref(server);
		} else {
			objunlock(server);
		}
		cloop = init_bucket_loop(server->connex);
		while (cloop && (connex = next_bucket_loop(cloop))) {
			objlock(connex);
			if (connex->sessions && (bucket_list_cnt(connex->sessions) > 254)) {
				objunlock(connex);
				objunref(connex);
				/* if im overflowing get next or add new*/
				objlock(server);
				if (!(connex = next_bucket_loop(cloop))) {
					if ((connex = radconnect(server))) {
						objunlock(server);
						objref(server);
					} else {
						break;
					}
				} else {
					objunlock(server);
				}
				objlock(connex);
			}

			connex->id++;
			if (hint) {
				packet = hint->packet;
				session = hint;
				packet->id = connex->id;
				session->id = packet->id;
				session->retries = 2;
				if (!connex->sessions) {
					connex->sessions = create_bucketlist(4, hash_session);
				}
				addtobucket(connex->sessions, session);
			} else {
				packet->id = connex->id;
				session = rad_session(packet, connex, userpass, read_cb, cb_data);
			}
			session->minserver = server->id;
			objunlock(connex);

			if (session->passwd) {
				addradattrpasswd(packet, session->passwd,  server->secret);
			}

			vector = addradattr(packet, RAD_ATTR_MESSAGE, NULL, RAD_AUTH_TOKEN_LEN);
			len = packet->len;
			packet->len = htons(len);
			md5hmac(vector + 2, packet, len, server->secret, strlen(server->secret));

			scnt = send(connex->socket->sock, packet, len, 0);
			memset(packet->attrs + session->olen - RAD_AUTH_HDR_LEN, 0, len - session->olen);
			packet->len = session->olen;

			objunref(connex);
			if (len == scnt) {
				session->sent = curtime;
				objunref(session);
				objunref(server);
				objunref(hint);
				objunref(cloop);
				objunref(sloop);
				return (0);
			} else {
				remove_bucket_item(connex->sessions, session);
			}
		}
		objunref(server);
		objunref(cloop);
	}
	objunref(sloop);
	objunref(hint);

	return (-1);
}

/** @brief Send radius packet.
  * @param packet Radius packet to send.
  * @param userpass Userpassword if required (added last requires special processing)
  * @param read_cb Callback to call when response arrives.
  * @param cb_data Reference to pass to callback.
  * @returns 0 on success.*/
extern int send_radpacket(struct radius_packet *packet, const char *userpass, radius_cb read_cb, void *cb_data) {
	return (_send_radpacket(packet, userpass, NULL, read_cb, cb_data));
}

static int resend_radpacket(struct radius_session *session) {
	return (_send_radpacket(NULL, NULL, session, NULL, NULL));
}

static void rad_resend(struct radius_connection *connex) {
	struct radius_session *session;
	struct bucket_loop *bloop;
	struct timeval tv;
	unsigned int tdiff, len, scnt;
	unsigned char *vector;

	gettimeofday(&tv, NULL);

	bloop=init_bucket_loop(connex->sessions);
	while (bloop && (session = next_bucket_loop(bloop))) {
		tdiff = tv.tv_sec - session->sent.tv_sec;
		if (tdiff > 3) {
			if (!session->retries) {
				remove_bucket_loop(bloop);
				resend_radpacket(session);
				objunref(session);
				continue;
			}

			if (session->passwd) {
				addradattrpasswd(session->packet, session->passwd, connex->server->secret);
			}

			vector = addradattr(session->packet, RAD_ATTR_MESSAGE, NULL, RAD_AUTH_TOKEN_LEN);
			len = session->packet->len;
			session->packet->len = htons(len);
			md5hmac(vector + 2, session->packet, len, connex->server->secret, strlen(connex->server->secret));

			scnt = send(connex->socket->sock, session->packet, len, 0);
			memset(session->packet->attrs + session->olen - RAD_AUTH_HDR_LEN, 0, len - session->olen);
			session->packet->len = session->olen;
			session->sent = tv;
			session->retries--;
			if (scnt != len) {
				remove_bucket_loop(bloop);
				resend_radpacket(session);
				objunref(session);
			}
		}
		objunref(session);
	}
	objunref(bloop);
}

static void radius_recv(void **data) {
	struct radius_connection *connex = *data;
	struct radius_packet *packet;
	unsigned char buff[RAD_AUTH_PACKET_LEN];
	unsigned char rtok[RAD_AUTH_TOKEN_LEN];
	unsigned char rtok2[RAD_AUTH_TOKEN_LEN];
	struct radius_session *session;
	int chk, plen;

	chk = recv(connex->socket->sock, buff, 4096, 0);

	if (chk < 0) {
		if (errno == ECONNREFUSED) {
			printf("Connection Bad\n");
		}
	} else
		if (chk == 0) {
			objlock(connex->server);
			printf("Taking server off line for %is\n", connex->server->timeout);
			gettimeofday(&connex->server->service, NULL);
			connex->server->service.tv_sec += connex->server->timeout;
			objunlock(connex->server);
		}

	packet = (struct radius_packet *)&buff;
	plen = ntohs(packet->len);

	if ((chk < plen) || (chk <= RAD_AUTH_HDR_LEN)) {
		printf("OOps Did not get proper packet\n");
		return;
	}

	memset(buff + plen, 0, RAD_AUTH_PACKET_LEN - plen);

	if (!(session = bucket_list_find_key(connex->sessions, &packet->id))) {
		printf("Could not find session\n");
		return;
	}

	memcpy(rtok, packet->token, RAD_AUTH_TOKEN_LEN);
	memcpy(packet->token, session->request, RAD_AUTH_TOKEN_LEN);
	md5sum2(rtok2, packet, plen, connex->server->secret, strlen(connex->server->secret));

	if (md5cmp(rtok, rtok2)) {
		printf("Invalid Signature");
		return;
	}

	if (session->read_cb) {
		packet->len = plen;
		session->read_cb(packet, session->cb_data);
	}

	remove_bucket_item(connex->sessions, session);
	objunref(session);
}

static void *rad_return(void *data) {
	struct radius_connection *connex = data;
	fd_set  rd_set, act_set;
	struct  timeval tv;
	int selfd;

	FD_ZERO(&rd_set);
	FD_SET(connex->socket->sock, &rd_set);

	while (framework_threadok()) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 200000;

		selfd = select(connex->socket->sock + 1, &act_set, NULL, NULL, &tv);

		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			rad_resend(connex);
			continue;
		} else
			if (selfd < 0) {
				break;
			}

		if (FD_ISSET(connex->socket->sock, &act_set)) {
			radius_recv(data);
		}
		rad_resend(connex);
	}

	return NULL;
}

static void del_radconnect(void *data) {
	struct radius_connection *connex = data;

	objunref(connex->server);
	objunref(connex->sessions);
	objunref(connex->socket);
}

static struct radius_connection *radconnect(struct radius_server *server) {
	struct radius_connection *connex;
	int val = 1;

	if ((connex = objalloc(sizeof(*connex), del_radconnect))) {
		if ((connex->socket = udpconnect(server->name, server->authport, NULL))) {
			if (!server->connex) {
				server->connex = create_bucketlist(0, hash_connex);
			}
			setsockopt(connex->socket->sock, SOL_IP, IP_RECVERR,(char *)&val, sizeof(val));
			connex->server = server;
			genrand(&connex->id, sizeof(connex->id));
			addtobucket(server->connex, connex);
			framework_mkthread(rad_return, NULL, NULL, connex, 0);
		}
	}
	return (connex);
}

/** @brief Return first packet attribute.
  *
  * Used with radius_attr_next() to iterate through attributes.
  * @param packet Radius packet.
  * @returns Pointer to next attribute*/
extern unsigned char *radius_attr_first(struct radius_packet *packet) {
	return (packet->attrs);
}

/** @brief Return next packet attribute.
  * @param packet Radius packet.
  * @param attr Last attribute.
  * @returns Pointer to next attribute.*/
extern unsigned char *radius_attr_next(struct radius_packet *packet, unsigned char *attr) {
	int offset = (packet->len - RAD_AUTH_HDR_LEN) - (attr - packet->attrs);

	if (!(offset - attr[1])) {
		return NULL;
	}

	return (attr + attr[1]);
}

/** @}*/
