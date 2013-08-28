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

#ifndef _FW_PRIVATE_H
#define _FW_PRIVATE_H

#ifdef HAVE_LINUX_IP_H
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#endif

/*from sslutils iputil is the only consumer*/
void dtsl_serveropts(struct fwsocket *sock);
void dtlshandltimeout(struct fwsocket *sock);

/*for main.c*/
int startthreads(void);
void jointhreads(void);
int thread_signal(int sig);

#ifdef HAVE_LINUX_IP_H
union l4hdr {
	struct tcphdr tcp;
	struct udphdr udp;
	struct icmphdr icmp;
};
#endif

#endif
