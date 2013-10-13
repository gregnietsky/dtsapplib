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

/** @defgroup LIB-Thread Posix thread interface
  * @ingroup LIB
  * @brief Functions for starting and managing threads.
  *
  * The thread interface consists of a management thread managing
  * a hashed bucket list of threads running optional clean up when done.
  * @addtogroup LIB-Thread
  * @{
  * @file
  * @brief Functions for starting and managing threads.
  *
  * The thread interface consists of a management thread managing
  * a hashed bucket list of threads running optional clean up when done.*/

#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>

#ifndef SIGHUP
/** @brief Define SIGHUP as 1 if its not defined.*/
#define SIGHUP		1
#endif

#include "include/dtsapp.h"

/** @brief 32 bit magic value to help determine thread is ok*/
#define THREAD_MAGIC 0xfeedf158

/** @brief Thread status a thread can be disabled by unsetting TL_THREAD_RUN*/
enum threadopt {
	/** @brief No status*/
	TL_THREAD_NONE  = 1 << 0,
	/** @brief thread is marked as running*/
	TL_THREAD_RUN   = 1 << 1,
	/** @brief thread is marked as complete*/
	TL_THREAD_DONE  = 1 << 2
};

/** @brief thread struct used to create threads data needs to be first element*/
struct thread_pvt {
	/** @brief Reference to data held on thread creation*/
	void			*data;
	/** @brief Magic number*/
	int			magic;
	/** @brief Thread information*/
	pthread_t		thr;
	/** @brief Thread cleanup callback
	  * @see threadcleanup*/
	threadcleanup		cleanup;
	/** @brief Thread function
	  * @see threadfunc*/
	threadfunc		func;
	/** @brief Thread signal handler
	  * @see threadsighandler*/
	threadsighandler	sighandler;
	/** @brief thread options
	  * @see threadopt_flags*/
	enum                    threadopt flags;
};

/** @brief Global threads data*/
struct threadcontainer {
	/** @brief Hashed bucket list of threads.*/
	struct bucket_list	*list;
	/** @brief Manager thread.*/
	struct thread_pvt	*manager;
};

/** @brief Thread control data.*/
struct threadcontainer *threads = NULL;

static int hash_thread(const void *data, int key) {
	const struct thread_pvt *thread = data;
	const pthread_t *hashkey = (key) ? data : &thread->thr;
	int ret;

	ret = jenhash(hashkey, sizeof(pthread_t), 0);
	return (ret);
}

static void close_threads(void *data) {
	if (threads && threads->list) {
		objunref(threads->list);
	}

	if (threads && threads->manager) {
		objunref(threads->manager);
	}
	threads = NULL;
}

/** @brief let threads check there status by passing in a pointer to there data
  *
  * @param data Reference to thread data
  * @return 0 if the thread should terminate.*/
extern int framework_threadok(void *data) {
	struct thread_pvt *thr = data;

	if (thr && (thr->magic == THREAD_MAGIC)) {
		return (testflag(thr, TL_THREAD_RUN));
	}
	return (0);
}

/*
 * close all threads when we get SIGHUP
 */
static int manager_sig(int sig, void *data) {
	struct thread_pvt *thread = data;

	switch(sig) {
		case SIGHUP:
			clearflag(thread, TL_THREAD_RUN);
			break;
	}
	return (1);
}

/*
 * loop through all threads till they stoped
 * setting stop will flag threads to stop
 */
static void *managethread(void **data) {
	struct thread_pvt *mythread = threads->manager;
	struct thread_pvt *thread;
	struct bucket_loop *bloop;
	pthread_t me;
	int stop = 0;

	me = pthread_self();
	while(bucket_list_cnt(threads->list)) {
		bloop = init_bucket_loop(threads->list);
		while (bloop && (thread = next_bucket_loop(bloop))) {
			/*this is my call im done*/
			if (pthread_equal(thread->thr, me)) {
				/* im going to leave the list and try close down all others*/
				if (mythread && !(testflag(mythread, TL_THREAD_RUN))) {
					/*remove from thread list and disable adding new threads*/
					remove_bucket_loop(bloop);
					objlock(threads);
					threads->manager = NULL;
					objunlock(threads);

					stop = 1;
				}
				objunref(thread);
				continue;
			}

			objlock(thread);
			if (stop && (thread->flags & TL_THREAD_RUN) && !(thread->flags & TL_THREAD_DONE)) {
				thread->flags &= ~TL_THREAD_RUN;
				objunlock(thread);
			} else if ((thread->flags & TL_THREAD_DONE) || pthread_kill(thread->thr, 0)) {
				objunlock(thread);
				remove_bucket_loop(bloop);
				if (thread->cleanup) {
					thread->cleanup(thread->data);
				}
				objunref(thread->data);
				objunref(thread);
			} else {
				objunlock(thread);
			}
			objunref(thread);
		}
		stop_bucket_loop(bloop);
#ifdef __WIN32__
		Sleep(10);
#else
		usleep(100000);
#endif
	}

	objunref(threads);
	threads = NULL;

	return NULL;
}

/** @brief  initialise the threadlist  start manager thread
  *
  * @returns 1 On success 0 on failure.*/
extern int startthreads(void) {
	if (!threads && !(threads = objalloc(sizeof(*threads), close_threads))) {
		return (0);
	}

	if (!threads->list && !(threads->list = create_bucketlist(4, hash_thread))) {
		objunref(threads);
		return (0);
	}

	if (!threads->manager && !(threads->manager = framework_mkthread(managethread, NULL, manager_sig, NULL))) {
		objunref(threads);
		return (0);
	}

	return (1);
}

/** @brief Stoping the manager thread will stop all other threads.*/
extern void stopthreads(void) {
	if (threads) {
		clearflag(threads->manager, TL_THREAD_RUN);
	}
}

static void *threadwrap(void *data) {
	struct thread_pvt *thread = data;
	void *ret = NULL;

	if (thread && thread->func) {
		setflag(thread, TL_THREAD_RUN);
		ret = thread->func(&thread->data);
		setflag(thread, TL_THREAD_DONE);
	}

	/* The manager thread will clean em up normally manager threead will turn threads off and sets manager to null*/
	if (!threads || !threads->manager) {
		if (thread->cleanup) {
			thread->cleanup(thread->data);
		}
		objunref(thread->data);
		objunref(thread);
	}

	return (ret);
}

/** @brief create a thread result must be unreferenced
  *
  * @param func Function to run thread on.
  * @param cleanup Cleanup function to run.
  * @param sig_handler Thread signal handler.
  * @param data Data to pass to callbacks.
  * @returns a thread structure that must be un referencend.*/
extern struct thread_pvt *framework_mkthread(threadfunc func, threadcleanup cleanup, threadsighandler sig_handler, void *data) {
	struct thread_pvt *thread;

	/* dont allow threads if no manager or it not started*/
	if ((!threads || !threads->manager) && (func != managethread)) {
		return NULL;
	}

	if (!(thread = objalloc(sizeof(*thread), NULL))) {
		return NULL;
	}

	thread->data = data;
	thread->flags = 0;
	thread->cleanup = cleanup;
	thread->sighandler = sig_handler;
	thread->func = func;
	thread->magic = THREAD_MAGIC;

	/* grab a ref to data for thread to make sure it does not go away*/
	objref(thread->data);
	if (pthread_create(&thread->thr, NULL, threadwrap, thread)) {
		objunref(thread->data);
		objunref(thread);
		return NULL;
	}

	/* am i up and running move ref to list*/
	if (!pthread_kill(thread->thr, 0)) {
		if (threads && threads->list) {
			objlock(threads);
			addtobucket(threads->list, thread);
			objunlock(threads);
			return (thread);
		} else {
			objunref(thread->data);
			objunref(thread);
		}
	} else {
		objunref(thread->data);
		objunref(thread);
	}

	return NULL;
}

/** @brief Join the manager thread.
  *
  * This will be done when you have issued stopthreads and are waiting
  * for threads to exit.*/
extern void jointhreads(void) {
	if (threads && threads->manager) {
		pthread_join(threads->manager->thr, NULL);
	}
}

/*
 * find the thread the signal was delivered to
 * if the signal was handled returns 1
 * if the thread could not be handled returns -1
 * returns 0 if not for thread
 * NB sending a signal to the current thread while threads is locked
 * will cause a deadlock.
 */
/*static int thread_signal(int sig) {
	struct thread_pvt *thread;
	pthread_t me;
	int ret = 0;

	me = pthread_self();
	if ((thread = bucket_list_find_key(threads->list, &me))) {
		if (thread->sighandler) {
			thread->sighandler(sig, thread);
			ret = 1;
		} else {
			ret = -1;
		}
		objunref(thread);
	}
	return (ret);
}*/

/** @}*/
