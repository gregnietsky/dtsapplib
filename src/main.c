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

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/file.h>

#include "include/dtsapp.h"
#include "include/private.h"

static struct framework_core *framework_core_info;

#ifndef __WIN32__
/*
 * handle signals to cleanup gracefully on exit
 */
static void framework_sig_handler(int sig, siginfo_t *si, void *unused) {
	/* flag and clean all threads*/
	switch (sig) {
		case SIGUSR1:
		case SIGUSR2:
		case SIGHUP:
		case SIGALRM:
			if (!thread_signal(sig) && framework_core_info->sig_handler) {
				framework_core_info->sig_handler(sig, si, unused);
			}
			break;
		case SIGTERM:
		case SIGINT:
			framework_shutdown();
			/* no break */
		default
				:
			if (framework_core_info->sig_handler) {
				framework_core_info->sig_handler(sig, si, unused);
			}
			/* no break */
	}
}
#endif

/*
 * Print gnu snippet at program run
 */
static void printgnu(struct framework_core *ci) {
	printf("%s\n\nCopyright (C) %i %s <%s>\n"
		   "        %s\n\n"
		   "    This program comes with ABSOLUTELY NO WARRANTY\n"
		   "    This is free software, and you are welcome to redistribute it\n"
		   "    under certain condition\n\n", ci->progname, ci->year, ci->developer, ci->email, ci->www);
}

static pid_t daemonize() {
#ifndef __WIN32__
	pid_t	forkpid;

	/* fork and die daemonize*/
	forkpid = fork();
	if (forkpid > 0) {
		/* im all grown up and can pass onto child*/
		exit(0);
	} else
		if (forkpid < 0) {
			/* could not fork*/
			exit(-1);
		}

	/* Dont want these as a daemon*/
	signal(SIGTSTP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/*set pid for consistancy i was 0 when born*/
	forkpid = getpid();
	return (forkpid);
#else
	return -1;
#endif
}

/*
 * create pid / run file and hold a exclusive lock on it
 */
static int lockpidfile(struct framework_core *ci) {
	int lck_fd = -1;
#ifndef __WIN32__
	char pidstr[12];

	sprintf(pidstr,"%i\n", (int)ci->my_pid);
	if (ci->runfile &&
			((lck_fd = open(ci->runfile, O_RDWR|O_CREAT, 0640)) > 0) &&
			(!flock(lck_fd, LOCK_EX | LOCK_NB))) {
		if (write(lck_fd, pidstr, strlen(pidstr)) < 0) {
			close(lck_fd);
			lck_fd = -1;
		}
	} else
		if (lck_fd) {
			close(lck_fd);
			lck_fd = -1;
		} else {
			ci->flock = -1;
			return (0);
		}
	ci->flock = lck_fd;
#endif
	return (lck_fd);
}


#ifndef __WIN32__
/*
 * set up signal handler
 */
static void configure_sigact(struct sigaction *sa) {
	sa->sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa->sa_mask);
	sa->sa_sigaction = framework_sig_handler;
	sigaction(SIGINT, sa, NULL);
	sigaction(SIGTERM, sa, NULL);

	/*internal interupts*/
	sigaction(SIGUSR1, sa, NULL);
	sigaction(SIGUSR2, sa, NULL);
	sigaction(SIGHUP, sa, NULL);
	sigaction(SIGALRM, sa, NULL);
}
#endif

/*
 * initialise core
 */
#ifdef __WIN32__
extern struct framework_core *framework_mkcore(char *progname, char *name, char *email, char *web, int year, char *runfile) {
#else
extern struct framework_core *framework_mkcore(char *progname, char *name, char *email, char *web, int year, char *runfile, syssighandler sigfunc) {
#endif
	struct framework_core *core_info = NULL;

	if (!(core_info = malloc(sizeof(*core_info)))) {
		return NULL;
	}

#ifndef __WIN32__
	if (core_info && !(core_info->sa = malloc(sizeof(*core_info->sa)))) {
		free(core_info);
		return NULL;
	}
#endif

	ALLOC_CONST(core_info->developer, name);
	ALLOC_CONST(core_info->email, email);
	ALLOC_CONST(core_info->www, web);
	ALLOC_CONST(core_info->runfile, runfile);
	ALLOC_CONST(core_info->progname, progname);
	core_info->year = year;
#ifndef __WIN32__
	core_info->sig_handler = sigfunc;
#endif

	return (core_info);
}

/*
 * free core
 */
static void framework_free(struct framework_core *ci) {
	if (!ci) {
		return;
	}

	if (ci->developer) {
		free((char *)ci->developer);
	}
	if (ci->email) {
		free((char *)ci->email);
	}
	if (ci->www) {
		free((char *)ci->www);
	}
	if (ci->sa) {
		free(ci->sa);
	}
	if (ci->flock >= 0) {
		close(ci->flock);
	}
	if (ci->runfile) {
		if (ci->flock >= 0) {
			unlink(ci->runfile);
		}
		free((char *)ci->runfile);
	}
}

/*
 * daemonise and start thread manager
 */
extern int framework_init(int argc, char *argv[], frameworkfunc callback, struct framework_core *core_info) {
	int ret = 0;

	seedrand();
	sslstartup();

	framework_core_info = core_info;

	/*prinit out a GNU licence summary*/
	printgnu(core_info);

	/* fork the process to daemonize it*/
	core_info->my_pid = daemonize();

	if (lockpidfile(core_info) < 0) {
		printf("Could not lock pid file Exiting\n");
		framework_free(core_info);
		return (-1);
	}

#ifndef __WIN32__
	/* interupt handler close clean on term so physical is reset*/
	configure_sigact(core_info->sa);
#endif

	/*init the threadlist start thread manager*/
	if (!startthreads()) {
		printf("Memory Error could not start threads\n");
		framework_free(core_info);
		return (-1);
	}

	/*run the code from the application*/
	if (callback) {
		ret = callback(argc, argv);
	}

	/*join the manager thread its the last to go*/
	if (!ret) {
		jointhreads();
	} else {
		framework_shutdown();
	}

	/* turn off the lights*/
	framework_free(core_info);
	return (ret);
}
