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

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include "include/dtsapp.h"

/* add one for ref obj's*/
#define REFOBJ_MAGIC		0xdeadc0de

/* ref counted objects*/
struct ref_obj {
	int	magic;
	int	cnt;
	int	size;
	pthread_mutex_t	*lock;
	objdestroy destroy;
	void	*data;
};

/* bucket list obj*/
struct blist_obj {
	int	hash;
	struct	blist_obj *next;
	struct	blist_obj *prev;
	struct	ref_obj *data;
};

/*bucket list to hold hashed objects in buckets*/
struct bucket_list {
	unsigned short	bucketbits;		/* number of buckets to create 2 ^ n masks hash*/
	unsigned int	count;
	blisthash	hash_func;
	struct		blist_obj **list;		/* array of blist_obj[buckets]*/
	pthread_mutex_t *locks;		/* locks for each bucket [buckets]*/
	int		*version;	/* version of the bucket to detect changes*/
};

/*
 * buckets are more complex than linked lists
 * to loop through them we will use a structure
 * that holds the bucket and head it needs to
 * be initialised and destroyed.
 */
struct bucket_loop {
	struct bucket_list *blist;
	int bucket;
	int version;
	unsigned int head_hash;
	unsigned int cur_hash;
	struct blist_obj *head;
	struct blist_obj *cur;
};

#define refobj_offset	sizeof(struct ref_obj);

extern void *objalloc(int size,objdestroy destructor) {
	struct ref_obj *ref;
	int asize;
	char *robj;

	asize  = size + refobj_offset;

	if ((robj = malloc(asize))) {
		memset(robj, 0, asize);
		ref = (struct ref_obj*)robj;
		if (!(ref->lock = malloc(sizeof(pthread_mutex_t)))) {
			free(robj);
			return NULL;
		}
		pthread_mutex_init(ref->lock, NULL);
		ref->magic = REFOBJ_MAGIC;
		ref->cnt = 1;
		ref->data = robj + refobj_offset;
		ref->size = size;
		ref->destroy = destructor;
		return (ref->data);
	}
	return NULL;
}

/* reference a object returns 0 on error*/
extern int objref(void *data) {
	char *ptr = data;
	struct ref_obj *ref;
	int ret = 0;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	if (!data || !ref || (ref->magic != REFOBJ_MAGIC)) {
		return (ret);
	}

	/*double check just incase im gone*/
	if (!pthread_mutex_lock(ref->lock)) {
		if ((ref->magic == REFOBJ_MAGIC) && (ref->cnt > 0)) {
			ref->cnt++;
			ret = ref->cnt;
		}
		pthread_mutex_unlock(ref->lock);
	}

	return (ret);
}

extern int objunref(void *data) {
	char *ptr = data;
	struct ref_obj *ref;
	int ret = -1;
	pthread_mutex_t *lock;

	if (!data) {
		return (ret);
	}

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	if ((ref->magic == REFOBJ_MAGIC) && (ref->cnt)) {
		pthread_mutex_lock(ref->lock);
		ref->cnt--;
		ret = ref->cnt;
		/* free the object its no longer in use*/
		if (!ret) {
			lock = ref->lock;
			ref->lock = NULL;
			ref->magic = 0;
			ref->size = 0;
			ref->data = NULL;
			if (ref->destroy) {
				ref->destroy(data);
			}
			pthread_mutex_unlock(lock);
			pthread_mutex_destroy(lock);
			free(lock);
			free(ref);
		} else {
			pthread_mutex_unlock(ref->lock);
		}
	}
	return (ret);
}

extern int objcnt(void *data) {
	char *ptr = data;
	int ret = -1;
	struct ref_obj *ref;

	if (!data) {
		return (ret);
	}

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(ref->lock);
		ret = ref->cnt;
		pthread_mutex_unlock(ref->lock);
	}
	return (ret);
}

extern int objsize(void *data) {
	char *ptr = data;
	int ret = 0;
	struct ref_obj *ref;

	if (!data) {
		return (ret);
	}

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(ref->lock);
		ret = ref->size;
		pthread_mutex_unlock(ref->lock);
	}
	return (ret);
}

extern int objlock(void *data) {
	char *ptr = data;
	struct ref_obj *ref;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	if (data && ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(ref->lock);
	}
	return (0);
}

extern int objtrylock(void *data) {
	char *ptr = data;
	struct ref_obj *ref;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	if (ref->magic == REFOBJ_MAGIC) {
		return ((pthread_mutex_trylock(ref->lock)) ? -1 : 0);
	}
	return (-1);
}

extern int objunlock(void *data) {
	char *ptr = data;
	struct ref_obj *ref;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_unlock(ref->lock);
	}
	return (0);
}

static void empty_buckets(void *data) {
	struct bucket_list *blist = data;
	struct bucket_loop *bloop;
	void *entry;

	bloop = init_bucket_loop(blist);
	while (bloop && (entry = next_bucket_loop(bloop))) {
		remove_bucket_loop(bloop);
		objunref(entry);
	}
	stop_bucket_loop(bloop);
}

/*
 * a bucket list is a ref obj the "list" element is a
 * array of "bucket" entries each has a hash
 * the default is to hash the memory when there is no call back
 */
extern void *create_bucketlist(int bitmask, blisthash hash_function) {
	struct bucket_list *new;
	short int buckets, cnt;

	buckets = (1 << bitmask);

	/* allocate session bucket list memory*/
	if (!(new = objalloc(sizeof(*new) + (sizeof(void*) + sizeof(pthread_mutex_t) + sizeof(int)) * buckets, empty_buckets))) {
		return NULL;
	}

	/*initialise each bucket*/
	new->bucketbits = bitmask;
	new->list = (void *)((char*)new + sizeof(*new));
	for (cnt = 0; cnt < buckets; cnt++) {
		if ((new->list[cnt] = malloc(sizeof(*new->list[cnt])))) {
			memset(new->list[cnt], 0, sizeof(*new->list[cnt]));
		}
	}

	/*next pointer is pointer to locks*/
	new->locks = (void *)&new->list[buckets];
	for (cnt = 0; cnt < buckets; cnt++) {
		pthread_mutex_init(&new->locks[cnt], NULL);
	}

	/*Next up version array*/
	new->version = (void *)&new->locks[buckets];

	new->hash_func = hash_function;

	return (new);
}

static struct blist_obj *blist_gotohash(struct blist_obj *cur, unsigned int hash, int bucketbits) {
	struct blist_obj *lhead = cur;

	if ((hash << bucketbits) < 0) {
		do {
			lhead = lhead->prev;
		} while ((lhead->hash > hash) && lhead->prev->next);
	} else {
		while (lhead && lhead->next && (lhead->next->hash < hash)) {
			lhead = lhead->next;
		}
	}

	return (lhead);
}

static int gethash(struct bucket_list *blist, const void *data, int key) {
	const char *ptr = data;
	struct ref_obj *ref;
	int hash = 0;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	if (blist->hash_func) {
		hash = blist->hash_func(data, key);
	} else if (ref && (ref->magic == REFOBJ_MAGIC)) {
		hash = jenhash(data, ref->size, 0);
	}
	return (hash);
}

/*
 * add a ref to the object for the bucket list
 */
extern int addtobucket(struct bucket_list *blist, void *data) {
	char *ptr = data;
	struct ref_obj *ref;
	struct blist_obj *lhead, *tmp;
	unsigned int hash, bucket;

	if (!objref(blist)) {
		return (0);
	}

	if (!objref(data)) {
		objunref(blist);
		return (0);
	}

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj*)ptr;

	hash = gethash(blist, data, 0);
	bucket = ((hash >> (32 - blist->bucketbits)) & ((1 << blist->bucketbits) - 1));

	pthread_mutex_lock(&blist->locks[bucket]);
	lhead = blist->list[bucket];
	/*no head or non null head*/
	if (!lhead || lhead->prev) {
		if (!(tmp = malloc(sizeof(*tmp)))) {
			pthread_mutex_unlock(&blist->locks[bucket]);
			objunref(data);
			objunref(blist);
			return (0);
		}
		memset(tmp, 0, sizeof(*tmp));
		tmp->hash = hash;
		tmp->data = ref;

		/*there is no head*/
		if (!lhead) {
			blist->list[bucket] = tmp;
			tmp->prev = tmp;
			tmp->next = NULL;
		/*become new head*/
		} else if (hash < lhead->hash) {
			tmp->next = lhead;
			tmp->prev = lhead->prev;
			lhead->prev = tmp;
			blist->list[bucket] = tmp;
		/*new tail*/
		} else if (hash > lhead->prev->hash) {
			tmp->prev = lhead->prev;
			tmp->next = NULL;
			lhead->prev->next = tmp;
			lhead->prev = tmp;
		/*insert entry*/
		} else {
			lhead = blist_gotohash(lhead, hash, blist->bucketbits);
			tmp->next = lhead->next;
			tmp->prev = lhead;

			if (lhead->next) {
				lhead->next->prev = tmp;
			} else {
				blist->list[bucket]->prev = tmp;
			}
			lhead->next = tmp;
		}
	} else {
		/*set NULL head*/
		lhead->data = ref;
		lhead->prev = lhead;
		lhead->next = NULL;
		lhead->hash = hash;
	}

	blist->version[bucket]++;
	pthread_mutex_unlock(&blist->locks[bucket]);

	objlock(blist);
	blist->count++;
	objunlock(blist);
	objunref(blist);

	return (1);
}

/*
 * create a bucket loop and lock the list
 */
extern struct bucket_loop *init_bucket_loop(struct bucket_list *blist) {
	struct bucket_loop *bloop = NULL;

	if (blist && (bloop = objalloc(sizeof(*bloop), NULL))) {
		objref(blist);
		bloop->blist = blist;
		bloop->bucket = 0;
		pthread_mutex_lock(&blist->locks[bloop->bucket]);
		bloop->head = blist->list[0];
		if (bloop->head) {
			bloop->head_hash = bloop->head->hash;
		};
		bloop->version = blist->version[0];
		pthread_mutex_unlock(&blist->locks[bloop->bucket]);
	}

	return (bloop);
}

/*
 * release the bucket loop and unref list
 */
extern void stop_bucket_loop(struct bucket_loop *bloop) {

	if (bloop) {
		objunref(bloop->blist);
		objunref(bloop);
	}
}

/*
 * return the next object (+ref) in the list
 */
extern void *next_bucket_loop(struct bucket_loop *bloop) {
	struct bucket_list *blist = bloop->blist;
	struct ref_obj *entry = NULL;
	void *data = NULL;

	pthread_mutex_lock(&blist->locks[bloop->bucket]);
	if (bloop->head_hash && (blist->version[bloop->bucket] != bloop->version)) {
		/* bucket has changed unexpectedly i need to ff/rew to hash*/
		bloop->head = blist_gotohash(blist->list[bloop->bucket], bloop->head_hash + 1, blist->bucketbits);
		/*if head has gone find next suitable ignore any added*/
		while (bloop->head && (bloop->head->hash < bloop->head_hash)) {
			bloop->head = bloop->head->next;
		}
	}

	while (!bloop->head || !bloop->head->prev) {
		pthread_mutex_unlock(&blist->locks[bloop->bucket]);
		bloop->bucket++;
		if (bloop->bucket < (1 << blist->bucketbits)) {
			pthread_mutex_lock(&blist->locks[bloop->bucket]);
			bloop->head = blist->list[bloop->bucket];
		} else {
			return NULL;
		}
	}

	if (bloop->head) {
		bloop->cur = bloop->head;
		entry = (bloop->head->data) ? bloop->head->data : NULL;
		data = (entry) ? entry->data : NULL;
		objref(data);
		bloop->head = bloop->head->next;
		bloop->head_hash = (bloop->head) ? bloop->head->hash : 0;
		bloop->cur_hash = (bloop->cur) ? bloop->cur->hash : 0;
	}
	pthread_mutex_unlock(&blist->locks[bloop->bucket]);

	return (data);
}

extern void remove_bucket_item(struct bucket_list *blist, void *data) {
	struct blist_obj *entry;
	int hash, bucket;

	hash = gethash(blist, data, 0);
	bucket = ((hash >> (32 - blist->bucketbits)) & ((1 << blist->bucketbits) - 1));

	pthread_mutex_lock(&blist->locks[bucket]);
	entry = blist_gotohash(blist->list[bucket], hash + 1, blist->bucketbits);
	if (entry && entry->hash == hash) {
		if (entry->next && (entry == blist->list[bucket])) {
			entry->next->prev = entry->prev;
			blist->list[bucket] = entry->next;
		} else if (entry->next) {
			entry->next->prev = entry->prev;
			entry->prev->next = entry->next;
		} else if (entry == blist->list[bucket]) {
			blist->list[bucket] = NULL;
		} else {
			entry->prev->next = NULL;
			blist->list[bucket]->prev = entry->prev;
		}
		objunref(entry->data->data);
		free(entry);
	}
	pthread_mutex_unlock(&blist->locks[bucket]);
}

/*
 * remove and unref the current data
 */
extern void remove_bucket_loop(struct bucket_loop *bloop) {
	struct bucket_list *blist = bloop->blist;
	int bucket = bloop->bucket;

	pthread_mutex_lock(&blist->locks[bloop->bucket]);
	/*if the bucket has altered need to verify i can remove*/
	if (bloop->cur_hash && (!bloop->cur || (blist->version[bloop->bucket] != bloop->version))) {
		bloop->cur = blist_gotohash(blist->list[bloop->bucket], bloop->cur_hash + 1, blist->bucketbits);
		if (!bloop->cur || (bloop->cur->hash != bloop->cur_hash)) {
			pthread_mutex_unlock(&blist->locks[bucket]);
			return;
		}
	}

	if (!bloop->cur) {
		pthread_mutex_unlock(&blist->locks[bucket]);
		return;
	}

	if (bloop->cur->next && (bloop->cur == blist->list[bucket])) {
		bloop->cur->next->prev = bloop->cur->prev;
		blist->list[bucket] = bloop->cur->next;
	} else if (bloop->cur->next) {
		bloop->cur->next->prev = bloop->cur->prev;
		bloop->cur->prev->next = bloop->cur->next;
	} else if (bloop->cur == blist->list[bucket]) {
		blist->list[bucket] = NULL;
	} else {
		bloop->cur->prev->next = NULL;
		blist->list[bucket]->prev = bloop->cur->prev;
	}

	objunref(bloop->cur->data->data);
	free(bloop->cur);
	bloop->cur_hash = 0;
	bloop->cur = NULL;
	blist->version[bucket]++;
	bloop->version++;
	pthread_mutex_unlock(&blist->locks[bucket]);

	objlock(blist);
	blist->count--;
	objunlock(blist);
}

extern int bucket_list_cnt(struct bucket_list *blist) {
	int ret = -1;

	if (blist) {
		objlock(blist);
		ret = blist->count;
		objunlock(blist);
	}
	return (ret);
}

extern void *bucket_list_find_key(struct bucket_list *blist, const void *key) {
	struct blist_obj *entry;
	int hash, bucket;

	if (!blist) {
		return (NULL);
	}

	hash = gethash(blist, key, 1);
	bucket = ((hash >> (32 - blist->bucketbits)) & ((1 << blist->bucketbits) - 1));

	pthread_mutex_lock(&blist->locks[bucket]);
	entry = blist_gotohash(blist->list[bucket], hash + 1, blist->bucketbits);
	if (entry && entry->data) {
		objref(entry->data->data);
	} else if (!entry) {
		pthread_mutex_unlock(&blist->locks[bucket]);
		return NULL;
	}

	pthread_mutex_unlock(&blist->locks[bucket]);

	if (entry->data && (entry->hash == hash)) {
		return (entry->data->data);
	} else if (entry->data) {
		objunref(entry->data->data);
	}

	return NULL;
}

extern void bucketlist_callback(struct bucket_list *blist, blist_cb callback, void *data2) {
	struct bucket_loop *bloop;
	void *data;

	if (!blist || !callback) {
		return;
	}

	bloop = init_bucket_loop(blist);
	while(blist && bloop && (data = next_bucket_loop(bloop))) {
		callback(data, data2);
		objunref(data);
	}
	stop_bucket_loop(bloop);
}
