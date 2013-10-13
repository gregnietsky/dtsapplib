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

/** @defgroup LIB-Usock Unix socket thread
  * @brief Attach a thread to a unix socket start a new thread on connect.
  *
  * @ingroup LIB
  * A thread is started on the sockect and will start a new client thread
  * on each connection with the socket as the data
  * @addtogroup LIB-Usock
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
#include <sys/stat.h>
#include <linux/un.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "include/dtsapp.h"

/** @brief Unix socket data structure*/
struct framework_sockthread {
	/** @brief Socket path*/
	char sock[UNIX_PATH_MAX+1];
	/** @brief Socket umask*/
	int mask;
	/** @brief Socket protocol*/
	int protocol;
	/** @brief Thread to begin on client connect
	  * @see threadfunc*/
	threadfunc	client;
	/** @brief Thread clean up function
	  * @see threadcleanup*/
	threadcleanup	cleanup;
};

/*
 * client sock server
 */
static void *unsock_serv(void **data) {
	struct framework_sockthread *unsock = *data;
	struct sockaddr_un	adr;
	unsigned int salen;
	struct	timeval	tv;
	fd_set	rd_set, act_set;
	int selfd;
	int on = 1;
	int *clfd;
	int fd, fdf;

	if ((fd = socket(PF_UNIX, unsock->protocol, 0)) < 0) {
		return NULL;
	}

	/* set user RW */
	umask(unsock->mask);

	fdf = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFD, fdf | O_NONBLOCK);

	memset(&adr, 0, sizeof(adr));
	adr.sun_family = PF_UNIX;
	salen = sizeof(adr);
	strncpy((char *)&adr.sun_path, unsock->sock, sizeof(adr.sun_path) -1);

	/*enable passing credentials*/
	setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

	if (bind(fd, (struct sockaddr *)&adr, salen)) {
		if (errno == EADDRINUSE) {
			/* delete old file*/
			unlink(unsock->sock);
			if (bind(fd, (struct sockaddr *)&adr, sizeof(struct sockaddr_un))) {
				perror("unsock_serv (bind)");
				close(fd);
				return NULL;
			}
		} else {
			perror("unsock_serv (bind)");
			close(fd);
			return NULL;
		}
	}

	if (listen(fd, 10)) {
		perror("client sock_serv (listen)");
		close(fd);
		return NULL;
	}

	FD_ZERO(&rd_set);
	FD_SET(fd, &rd_set);

	while (framework_threadok(data)) {
		act_set = rd_set;
		tv.tv_sec = 0;
		tv.tv_usec = 20000;

		selfd = select(fd + 1, &act_set, NULL, NULL, &tv);

		/*returned due to interupt continue or timed out*/
		if ((selfd < 0 && errno == EINTR) || (!selfd)) {
			continue;
		} else
			if (selfd < 0) {
				break;
			}

		if (FD_ISSET(fd, &act_set)) {
			clfd = objalloc(sizeof(int), NULL);
			if ((*clfd = accept(fd, (struct sockaddr *)&adr, &salen))) {
				framework_mkthread(unsock->client, unsock->cleanup, NULL, clfd);
			}
			objunref(clfd);
		}
	}

	close(fd);
	unlink(unsock->sock);

	return NULL;
}

/** @brief Create and run UNIX socket thread.
  *
  * @param sock Path to UNIX socket.
  * @param protocol Protocol number.
  * @param mask Umask for the socket.
  * @param connectfunc Thread to start on connect.
  * @param cleanup Thread cleanup callback.*/
extern void framework_unixsocket(char *sock, int protocol, int mask, threadfunc connectfunc, threadcleanup cleanup) {
	struct framework_sockthread *unsock;
	void *thread;

	unsock = objalloc(sizeof(*unsock), NULL);
	strncpy(unsock->sock, sock, UNIX_PATH_MAX);
	unsock->mask = mask;
	unsock->client = connectfunc;
	unsock->cleanup = cleanup;
	unsock->protocol = protocol;
	thread = framework_mkthread(unsock_serv, NULL, NULL, unsock);
	objunref(thread);
}

/** @}*/
