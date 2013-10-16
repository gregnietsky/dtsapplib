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

/** @addtogroup LIB-Thread
  * @{
  * @file
  * @brief Functions for starting and managing threads.
  *
  * The thread interface consists of a management thread managing
  * a hashed bucket list of threads running optional clean up when done.*/

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>

#ifndef SIGHUP
/** @brief Define SIGHUP as 1 if its not defined.*/
#define SIGHUP		1
#endif

#include "include/dtsapp.h"

/** @brief Thread status a thread can be disabled by unsetting TL_THREAD_RUN
  * @note bits 16-31 are useoptions see thread_option_flags*/
enum threadopt {
	/** @brief No status*/
	TL_THREAD_NONE		= 1 << 0,
	/** @brief thread is marked as running*/
	TL_THREAD_RUN		= 1 << 1,
	/** @brief thread is marked as complete*/
	TL_THREAD_DONE		= 1 << 2,
	/** @brief Quit when only manager is left
          * @note This flag is only valid for manager thread*/
	TL_THREAD_JOIN		= 1 << 3,
	/** @brief Quit when only manager is left
          * @note This flag is only valid for manager thread*/
	TL_THREAD_STOP		= 1 << 4,

	/** @brief Flag to enable pthread_cancel calls*/
	TL_THREAD_CAN_CANCEL	= 1 << 16,
	/** @brief Flag to enable pthread_cancel calls*/
	TL_THREAD_JOINABLE	= 1 << 17,
	TL_THREAD_RETURN	= 1 << 18
};

/** @brief thread struct used to create threads data needs to be first element*/
struct thread_pvt {
	/** @brief Reference to data held on thread creation*/
	void			*data;
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

/** @brief Automatically start manager thread.
  *
  * If threads have not been started and a thread is created the manager thread will be started.
  * once threads have stoped this will be set to zero manually starting startthreads will be possible.*/
int thread_can_start = 1;

static int32_t hash_thread(const void *data, int key) {
	const struct thread_pvt *thread = data;
	const pthread_t *th = (key) ? data : &thread->thr;
	return jenhash(th, sizeof(pthread_t), 0);
}

static void close_threads(void *data) {
	struct threadcontainer *tc = data;

	if (tc->list) {
		objunref(tc->list);
	}

	if (tc->manager) {
		objunref(tc->manager);
		tc->manager = NULL;
	}
	threads = NULL;
}

static void free_thread(void *data) {
	struct thread_pvt *thread = data;

	if (thread->data) {
		objunref(thread->data);
	}
}

static struct thread_pvt *get_thread_from_id() {
	struct thread_pvt *thr;
	struct threadcontainer *tc;
	pthread_t me;

	if (!(tc = (objref(threads)) ? threads : NULL)) {
		return NULL;
	}
	me = pthread_self();

	objlock(tc);
	thr = bucket_list_find_key(tc->list, &me);
	objunlock(tc);
	objunref(tc);
	return thr;
}


/** @brief let threads check there status by passing in a pointer to there data
  *
  * @param data Reference to thread data
  * @return 0 if the thread should terminate.*/
extern int framework_threadok() {
	struct thread_pvt *thr;
	int ret;

	thr = get_thread_from_id();
	ret =(thr) ? testflag(thr, TL_THREAD_RUN) : 0;
	objunref(thr);

	return ret;
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

/* if im here im the last thread*/
static void manage_clean(void *data) {

	/*make sure im still here when turning off*/
	objlock(threads);
	thread_can_start = 0;
	objunlock(threads);
	objunref(threads);
}

static void stop_threads(void *data, void *data2) {
	struct thread_pvt *thread = data;
	struct thread_pvt *man = data2;

	/*Dont footbullet*/
	if (!pthread_equal(man->thr, thread->thr)) {
		clearflag(thread, TL_THREAD_RUN);
		if (thread->sighandler) {
			pthread_kill(thread->thr, SIGTERM);
		}
		if (testflag(thread, TL_THREAD_CAN_CANCEL)) {
			pthread_cancel(thread->thr);
		}
	}
}

/*
 * loop through all threads till they stoped
 * setting stop will flag threads to stop
 */
static void *managethread(void *data) {
	struct thread_pvt *thread;
	int last = 0;

	if (!(thread = get_thread_from_id())) {
		return NULL;
	}

	for(;;) {
		/*if im the last one leave this is done locked to make sure no items are added/removed*/
		objlock(threads);
		if (!(bucket_list_cnt(threads->list) - last)) {
			if (threads->manager) {
				objunref(threads->manager);
				threads->manager = NULL;
			}
			objunlock(threads);
			objunref(thread);
			break;
		}
		objunlock(threads);

		/* Ive been joined so i can leave when im alone*/
		if (testflag(thread, TL_THREAD_JOIN)) {
			clearflag(thread, TL_THREAD_JOIN);
			last = 1;
		}

		/*Cancel all running threads*/
		if (testflag(thread, TL_THREAD_STOP)) {
			clearflag(thread, TL_THREAD_STOP);
			/* Stop any more threads*/
			objlock(threads);
			if (threads->manager) {
				objunref(threads->manager);
				threads->manager = NULL;
			}
			objunlock(threads);

			/* cancel all threads now that they stoped*/
			bucketlist_callback(threads->list, stop_threads, thread);
			last = 1;
		}
#ifdef __WIN32__
		Sleep(1000);
#else
		sleep(1);
#endif
	}
	return NULL;
}

/** @brief Initialise the threadlist and start manager thread
  *
  * @note There is no need to call this as it will start when first thread starts.
  * @returns 1 On success 0 on failure.*/
extern int startthreads(void) {
	struct threadcontainer *tc;

	tc = (objref(threads)) ? threads : NULL;

	if (tc) {
		objunref(tc);
		return 1;
	}

	if (!(tc = objalloc(sizeof(*threads), close_threads))) {
		return 0;
	}

	if (!tc->list && !(tc->list = create_bucketlist(4, hash_thread))) {
		objunref(tc);
		return 0;
	}

	threads = tc;
	if (!(tc->manager = framework_mkthread(managethread, manage_clean, manager_sig, NULL, THREAD_OPTION_JOINABLE | THREAD_OPTION_RETURN))) {
		objunref(tc);
		return 0;
	}

	return 1;
}

/** @brief Signal manager to stop and cancel all running threads.
  *
  * This should always be called at shutdown if there have been threads
  * started.
  * @see framework_init()
  * @see FRAMEWORK_MAIN()
  * @param join A non zero value to join the manager thread after flaging the shutdown.*/
extern void stopthreads(int join) {
	struct threadcontainer *tc;

	tc = (objref(threads)) ? threads : NULL;
	if (!tc) {
		return;
	}

	objlock(tc);
	if (tc->manager) {
		setflag(tc->manager, TL_THREAD_STOP);
		if (join) {
			setflag(tc->manager, TL_THREAD_JOIN);
			objunlock(tc);
			pthread_join(tc->manager->thr, NULL);
		} else {
			objunlock(tc);
		}
	} else {
		objunlock(tc);
	}
	objunlock(tc);
	objunref(tc);
}

static void thread_cleanup(void *data) {
	struct thread_pvt *thread = data;

	/*remove from thread list manager unrefs threads in cleanup run 1st*/
	remove_bucket_item(threads->list, thread);

	/*Run cleanup*/
	clearflag(thread, TL_THREAD_RUN);
	setflag(thread, TL_THREAD_DONE);
	if (thread->cleanup) {
		thread->cleanup(thread->data);
	}

	/*remove thread reference*/
	objunref(thread);
}

static void *threadwrap(void *data) {
	struct thread_pvt *thread = data;
	void *ret = NULL;
	int cnt;

	objref(thread);

	for(cnt = 0;!testflag(thread, TL_THREAD_RUN) && (cnt < 10); cnt++) {
		usleep(1000);
	}

	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	if (!testflag(thread, TL_THREAD_CAN_CANCEL)) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	}

	if (!testflag(thread, TL_THREAD_JOINABLE)) {
		pthread_detach(thread->thr);
	}

	if (cnt != 10) {
		pthread_cleanup_push(thread_cleanup, thread);
		ret = thread->func(thread->data);
		pthread_cleanup_pop(1);
	}

	return (ret);
}

/** @brief create a thread result must be unreferenced
  *
  * @note If the manager thread has not yet started this will start the manager thread
  * @param func Function to run thread on.
  * @param cleanup Cleanup function to run.
  * @param sig_handler Thread signal handler.
  * @param data Data to pass to callbacks.
  * @param flags Options of thread_option_flags passed
  * @returns a thread structure that must be un referencend.*/
extern struct thread_pvt *framework_mkthread(threadfunc func, threadcleanup cleanup, threadsighandler sig_handler, void *data, int flags) {
	struct thread_pvt *thread;
	struct threadcontainer *tc = NULL;

	/*Grab a reference for threads in this scope start up if we can*/
	if (!(tc = (objref(threads)) ? threads : NULL)) {
		if (!thread_can_start) {
			return NULL;
		} else if (!startthreads()) {
			return NULL;
		}
		if (!(tc = (objref(threads)) ? threads : NULL)) {
			return NULL;
		}
	}

	objlock(tc);
	/* dont allow threads if no manager or it not started*/
	if ((!tc->manager || !func) && (func != managethread)) {
		/*im shuting down*/
		objunlock(tc);
		objunref(tc);
		return NULL;
	} else if (!(thread = objalloc(sizeof(*thread), free_thread))) {
		/* could not create*/
		objunlock(tc);
		objunref(tc);
		return NULL;
	}

	thread->data = (objref(data)) ? data : NULL;
	thread->flags = flags << 16;
	thread->cleanup = cleanup;
	thread->sighandler = sig_handler;
	thread->func = func;
	objunlock(tc);

	/* start thread and check it*/
	if (pthread_create(&thread->thr, NULL, threadwrap, thread) || pthread_kill(thread->thr, 0)) {
		objunref(thread);
		objunref(tc);
		return NULL;
	}

	/*Activate the thread it needs to be flaged to run or it will die*/
	objlock(tc);
	addtobucket(tc->list, thread);
	setflag(thread, TL_THREAD_RUN);
	objunlock(tc);
	objunref(tc);

	if (testflag(thread, TL_THREAD_RETURN)) {
		return thread;
	} else {
		objunref(thread);
		return NULL;
	}
}

/** @brief Join the manager thread.
  *
  * This will be done when you have issued stopthreads and are waiting
  * for threads to exit.*/
extern void jointhreads(void) {
	struct threadcontainer *tc;

	tc = (objref(threads)) ? threads : NULL;
	if (!tc) {
		return;
	}

	objlock(tc);
	if (tc->manager) {
		setflag(tc->manager, TL_THREAD_JOIN);
		objunlock(tc);
		pthread_join(tc->manager->thr, NULL);
	} else {
		objunlock(tc);
	}
	objunref(tc);
}


#ifndef __WIN32
static int handle_thread_signal(struct thread_pvt *thread, int sig) {
	int ret;

	if (thread->sighandler) {
		thread->sighandler(sig, thread->data);
		ret = 1;
	} else {
		ret = -1;
	}
	return ret;
}
#endif

/** @brief Handle signal if its for me
  *
  * find the thread the signal was delivered to
  * if the signal was handled returns 1
  * if the thread could not be handled returns -1
  * returns 0 if no thread is found
  * NB sending a signal to the current thread while threads is locked
  * will cause a deadlock.
  * @warning This is not to be called directly but by the installed system signal handler.
  * @param sig Signal to pass.
  * @returns 1 on success -1 on error.*/
extern int thread_signal(int sig) {
	struct thread_pvt *thread = NULL;
	int ret = 0;

	if (!(thread = get_thread_from_id())) {
		return 0;
	}

#ifndef __WIN32
	switch(sig) {
		case SIGUSR1:
		case SIGUSR2:
		case SIGHUP:
		case SIGALRM:
			ret = handle_thread_signal(thread, sig);
			break;
		case SIGINT:
		case SIGTERM:
			ret = handle_thread_signal(thread, sig);
			printf("Kill %p\n", (void*)&thread->thr);
	}
#endif
	objunref(thread);
	return ret;
}

/** @}*/
