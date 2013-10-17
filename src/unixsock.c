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

/** @addtogroup LIB-Sock-Unix
  * @{
  * @file
  * @brief Attach a thread to a unix socket start a new thread on connect.
  *
  * A thread is started on the sockect and will start a new client thread
  * on each connection with the socket as the data*/

#ifdef __WIN32__
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif
#include <libgen.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/dtsapp.h"

/** @brief Unix socket server data structure*/
struct unixserv_sockthread {
	/** @brief Socket reference*/
	struct fwsocket	*sock;
	/** @brief Socket path*/
	char sockpath[UNIX_PATH_MAX+1];
	/** @brief Socket umask*/
	int mask;
	/** @brief Socket protocol*/
	int protocol;
	/** @brief Thread to begin on client connect
	  * @see threadfunc*/
	socketrecv	read;
	/** @brief Data reference passed to callback*/
	void		*data;
};

/** @brief Unix socket client data structure*/
struct unixclient_sockthread {
	/** @brief Socket reference*/
	struct fwsocket	*sock;
	/** @brief Client read callback
	  * @see socketrecv*/
	socketrecv	client;
	/** @brief Client endpoint tmp for SOCK_DGRAM.*/
	const char	*endpoint;
	/** @brief Data reference passed to callback*/
	void		*data;
};

/*
 * UNIX sock client
 */
static void *unsock_client(void *data) {
	struct unixclient_sockthread *unsock = data;
	struct fwsocket *sock = unsock->sock;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd;
	int on = 1;
	int fd, fdf;


	FD_ZERO(&rd_set);

	fd = sock->sock;
	fdf = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFD, fdf | O_NONBLOCK);
	/*enable passing credentials*/
	setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
	FD_SET(fd, &rd_set);

	while (framework_threadok()) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(fd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else if (selfd < 0) {
			break;
		}

		if (FD_ISSET(sock->sock, &act_set) && unsock->client) {
			unsock->client(sock, unsock->data);
		}
	}
	objunref(unsock);

	return NULL;
}

static void unixclient_sockthread_free(void *data) {
	struct unixclient_sockthread *uc = data;

	if (uc->sock) {
		objunref(uc->sock);
	}
	if (uc->data) {
		objunref(uc->data);
	}
	if (uc->endpoint) {
		if (!strlenzero(uc->endpoint)) {
			unlink(uc->endpoint);
		}
		free((void*)uc->endpoint);
	}
}

static int new_unixclientthread(struct fwsocket *fws, const char *endpoint, socketrecv read, void *data) {
	struct unixclient_sockthread *unsock;
	void *thread;

	if (!(unsock = objalloc(sizeof(*unsock), unixclient_sockthread_free))) {
		return 0;
	}

	unsock->sock = fws;
	unsock->data = (objref(data)) ? data : NULL;
	unsock->client = read;
	unsock->endpoint = endpoint;

	if (!(thread = framework_mkthread(unsock_client, NULL, NULL, unsock, THREAD_OPTION_RETURN))) {
		objunref(unsock);
		return 0;
	}
	objunref(thread);
	return 1;
}

/*
 * UNIX sock server
 */
static void *unsock_serv(void *data) {
	struct unixserv_sockthread *unsock = data;
	struct fwsocket *newsock, *sock;
	union sockstruct *adr;
	unsigned int salen;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd;
	int on = 1;
	int fd, fdf;

	/* set user RW */
	umask(unsock->mask);


	sock = unsock->sock;
	sock->flags |= SOCK_FLAG_UNIX;
	fd = sock->sock;

	fdf = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFD, fdf | O_NONBLOCK);

	adr = &sock->addr;
	memset(&adr->un, 0, sizeof(adr->un));
	adr->un.sun_family = PF_UNIX;
	salen = sizeof(adr->un);
	strncpy((char *)adr->un.sun_path, unsock->sockpath, sizeof(adr->un.sun_path) -1);

	/*enable passing credentials*/
	setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

	if (bind(fd, (struct sockaddr *)&adr->un, salen)) {
		if (errno == EADDRINUSE) {
			/* delete old file*/
			unlink(unsock->sockpath);
			if (bind(fd, (struct sockaddr *)&adr->un, sizeof(struct sockaddr_un))) {
				objunref(unsock);
				close(fd);
				return NULL;
			}
		} else {
			objunref(unsock);
			close(fd);
			return NULL;
		}
	}

	if (unsock->protocol == SOCK_STREAM) {
		if (listen(fd, 10)) {
			close(fd);
			objunref(unsock);
			return NULL;
		}
	}

	FD_ZERO(&rd_set);
	FD_SET(fd, &rd_set);

	while (framework_threadok()) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(fd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else if (selfd < 0) {
			break;
		}

		if (FD_ISSET(fd, &act_set)) {
			if (unsock->protocol == SOCK_STREAM) {
				if ((newsock = accept_socket(sock))) {
					if (!(new_unixclientthread(newsock, NULL, unsock->read, unsock->data))) {
						objunref(newsock);
					}
				}
			} else if (unsock->read) {
				unsock->read(sock, unsock->data);
				
			}
		}
	}

	close(fd);
	objunref(unsock);

	return NULL;
}

static void free_unixserv(void *data) {
	struct unixserv_sockthread *unsock = data;

	if (unsock->sock) {
		objunref(unsock->sock);
	}

	if (!strlenzero(unsock->sockpath)) {
		unlink(unsock->sockpath);
	}

	if (unsock->data) {
		objunref(data);
	}
}

/** @brief Create and run UNIX server socket thread.
  *
  * @param sock Path to UNIX socket.
  * @param protocol Protocol number.
  * @param mask Umask for the socket.
  * @param read Callback to call when there is data available.
  * @param data Data reference to pass to read callback.
  * @returns Reference to a socket*/
extern struct fwsocket *unixsocket_server(const char *sock, int protocol, int mask, socketrecv read, void *data) {
	struct unixserv_sockthread *unsock;

	if (!(unsock = objalloc(sizeof(*unsock), free_unixserv))) {
		return NULL;
	}

	strncpy(unsock->sockpath, sock, UNIX_PATH_MAX);
	unsock->mask = mask;
	unsock->read = read;
	unsock->protocol = protocol;
	unsock->data = (objref(data)) ? data : NULL;

	/*Create a UNIX socket structure*/
	if (!(unsock->sock = make_socket(PF_UNIX, protocol, 0, NULL))) {
		objunref(unsock);
		return NULL;
	}

	framework_mkthread(unsock_serv, NULL, NULL, unsock, 0);
	return (objref(unsock->sock)) ? unsock->sock : NULL;
}

/** @brief Create a client thread on the socket
  *
  * It is not recomended to use SOCK_DGRAM as it requires a socket endpoint [inode] created
  * this is done in /tmp using the basename of the socket and 6 random chars. this file is set to
  * have no permissions as we only need the inode.
  * @param sock Path to UNIX socket
  * @param protocol Either SOCK_STREAM or SOCK_DGRAM, SOCK_STREAM is recomended.
  * @param read Call back to call when read is ready.
  * @param data Reference to data to be returned in read callback.
  * @returns Socket file descriptor*/
extern struct fwsocket *unixsocket_client(const char *sock, int protocol, socketrecv read, void *data) {
	struct fwsocket *fws;
	union sockstruct caddr, *saddr;
	char *temp = NULL;
	const char *tmpsock;
	int salen;
	mode_t omask;

	/*Create a UNIX socket structure*/
	if (!(fws = make_socket(PF_UNIX, protocol, 0, NULL))) {
		return NULL;
	}

	/* bind my endpoint to temp file*/
	if (protocol == SOCK_DGRAM) {
		/*yip i want only a inode here folks*/
		omask = umask(S_IXUSR | S_IRUSR | S_IWUSR | S_IWGRP | S_IRGRP | S_IXGRP | S_IWOTH | S_IROTH | S_IXOTH);
		tmpsock = basename((char*)sock);
		temp = tempnam(NULL, tmpsock);
		if (strlenzero(temp)) {
			if (temp) {
				free(temp);
			}
			objunref(fws);
			return NULL;
		}

		/*Allocate address and connect to the client*/
		salen = sizeof(caddr.un);
		memset(&caddr.un, 0, salen);
		caddr.un.sun_family = PF_UNIX;
		strncpy((char *)caddr.un.sun_path, temp, sizeof(caddr.un.sun_path) -1);

		if (bind(fws->sock, (struct sockaddr *)&caddr.un, salen)) {
			/*reset umask*/
			umask(omask);
			if (temp) {
				if (!strlenzero(temp)) {
					unlink(temp);
				}
				free(temp);
			}
			objunref(fws);
			return NULL;
		}
		/*reset umask*/
		umask(omask);
	}

	/*Allocate address and connect to the server*/
	saddr =  &fws->addr;
	salen = sizeof(saddr->un);
	memset(&saddr->un, 0, salen);
	saddr->un.sun_family = PF_UNIX;
	strncpy((char *)saddr->un.sun_path, sock, sizeof(saddr->un.sun_path) -1);

	if (connect(fws->sock, (struct sockaddr *)&saddr->un, salen)) {
		if (temp) {
			if (!strlenzero(temp)) {
				unlink(temp);
			}
			free(temp);
		}
		objunref(fws);
		return NULL;
	}
	
	fws->flags |= SOCK_FLAG_UNIX;
	if (!(new_unixclientthread(fws, temp, read, data))) {
		if (temp) {
			if (!strlenzero(temp)) {
				unlink(temp);
			}
			free(temp);
		}
		objunref(fws);
		return NULL;
	}

	return (objref(fws)) ? fws : NULL;
}

/** @}*/
