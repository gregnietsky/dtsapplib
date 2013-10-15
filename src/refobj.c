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
  * @brief Referenced Lockable Objects.
  * @ingroup LIB-OBJ LIB-OBJ-Bucket
  * @addtogroup LIB-OBJ
  * @{*/


#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "include/dtsapp.h"

/* add one for ref obj's*/
/** @brief Magic number stored as first field of all referenced objects.*/
#define REFOBJ_MAGIC		0xdeadc0de

/* ref counted objects*/
/** @brief Internal structure of all referenced objects*/
struct ref_obj {
	/** @brief Memory integrity check used to prevent non refeferenced 
	  * objects been handled as referenced objects
	  * @see REFOBJ_MAGIC*/
	uint32_t	magic;
	/** @brief Reference count the oject will be freed when the reference
	  * count reaches 0*/
	uint32_t	cnt;
	/** @brief The size allocated to this object
	  * @warning this may be removed in future.*/
	size_t		size;
	/** @brief this is a pointer to the lock it may be changed to be the lock*/
	pthread_mutex_t	lock;
	/** @brief Function to call to clean up the data before its freed*/
	objdestroy	destroy;
	/** @brief Pointer to the data referenced.*/
	void		*data;
};

/** @}*/

/** @ingroup LIB-OBJ-Bucket
  * @brief Entry in a bucket list*/
struct blist_obj {
	/** @brief Hash value calculated from the data
	  * @warning this should not change during the life of this object*/
	int32_t		hash;
	/** @brief Next entry in the bucket*/
	struct		blist_obj *next;
	/** @brief Previous entry in the bucket*/
	struct		blist_obj *prev;
	/** @brief Reference to data held*/
	struct		ref_obj *data;
};

/** @ingroup LIB-OBJ-Bucket
  * @brief Bucket list, hold hashed objects in buckets*/
struct bucket_list {
	/** @brief number of buckets 2^n*/
	unsigned short	bucketbits;
	/** @brief Number of items held*/
	size_t		count;
	/** @brief Hash function called to calculate the hash and thus the bucket its placed in*/
	blisthash	hash_func;
	/** @brief Array of blist_obj one per bucket ie 2^bucketbits*/
	struct		blist_obj **list;
	/** @brief Array of locks one per bucket*/
	pthread_mutex_t *locks;
	/** @brief version of the bucket to detect changes during iteration (loop)*/
	size_t		*version;
};

/** @ingroup LIB-OBJ-Bucket
  */
/** @brief Bucket iterator
  *
  * buckets are more complex than linked lists to loop through them we
  * will use a structure that holds a reference to the bucket and head it needs to
  * be initialised and destroyed*/
struct bucket_loop {
	/** @brief Referenece to the bucket been itereated.*/
	struct bucket_list *blist;
	/** @brief Active bucket as determined by hash*/
	unsigned short bucket;
	/** @brief Our version check this with blist to determine if
	  * we must rewined and fast forward*/
	size_t version;
	/** @brief Hash of head if we need to comeback*/
	uint32_t head_hash;
	/** @brief Hash of cur if we need to comeback*/
	uint32_t cur_hash;
	/** @brief Current bucket*/
	struct blist_obj *head;
	/** @brief Current item*/
	struct blist_obj *cur;
};

/** @addtogroup LIB-OBJ
  * @{*/

/** @brief The size of ref_obj is the offset for the data*/
#define refobj_offset	sizeof(struct ref_obj);

/** @brief Allocate a referenced lockable object.
  *
  * Use malloc to allocate memory to contain the data lock and reference
  * the lock is initialised magic and reference set.
  * The data begins at the end of the ref_obj set a pointer to it and return.
  * @param size Size of the data buffer to allocate in addition to the reference.
  * @param destructor Function called before the memory is freed to cleanup.
  * @returns Pointer to a data buffer size big.*/
extern void *objalloc(int size,objdestroy destructor) {
	struct ref_obj *ref;
	int asize;
	char *robj;

	asize  = size + refobj_offset;

	if ((robj = malloc(asize))) {
		memset(robj, 0, asize);
		ref = (struct ref_obj *)robj;
		pthread_mutex_init(&ref->lock, NULL);
		ref->magic = REFOBJ_MAGIC;
		ref->cnt = 1;
		ref->data = robj + refobj_offset;
		ref->size = size;
		ref->destroy = destructor;
		return (ref->data);
	}
	return NULL;
}

/** @brief Reference a object.
  * @param data Data to obtain reference for.
  * @returns 0 on error or the current count (after incrementing)*/
extern int objref(void *data) {
	char *ptr = data;
	struct ref_obj *ref;
	int ret = 0;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj *)ptr;

	if (!data || !ref || (ref->magic != REFOBJ_MAGIC)) {
		return (ret);
	}

	/*double check just incase im gone*/
	if (!pthread_mutex_lock(&ref->lock)) {
		if ((ref->magic == REFOBJ_MAGIC) && (ref->cnt > 0)) {
			ref->cnt++;
			ret = ref->cnt;
		}
		pthread_mutex_unlock(&ref->lock);
	}

	return (ret);
}

/** @brief Drop reference held
  *
  * If the reference is the last reference call the destructor to clean up
  * and then free the memory used.
  * @warning The reference should not be used again and ideally set to NULL.
  * @param data Data we are droping a reference for
  * @returns -1 on error or the refrence count after decrementing.*/
extern int objunref(void *data) {
	char *ptr = data;
	struct ref_obj *ref;
	int ret = -1;

	if (!data) {
		return (ret);
	}

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj *)ptr;

	if ((ref->magic == REFOBJ_MAGIC) && (ref->cnt)) {
		pthread_mutex_lock(&ref->lock);
		ref->cnt--;
		ret = ref->cnt;
		/* free the object its no longer in use*/
		if (!ret) {
			ref->magic = 0;
			ref->size = 0;
			ref->data = NULL;
			if (ref->destroy) {
				ref->destroy(data);
			}
			pthread_mutex_unlock(&ref->lock);
			pthread_mutex_destroy(&ref->lock);
			free(ref);
		} else {
			pthread_mutex_unlock(&ref->lock);
		}
	}
	return (ret);
}

/** @brief Return current reference count
  *
  * @param data Pointer to determine active reference count.
  * @returns -1 on error or the current count.*/
extern int objcnt(void *data) {
	char *ptr = data;
	int ret = -1;
	struct ref_obj *ref;

	if (!data) {
		return (ret);
	}

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj *)ptr;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(&ref->lock);
		ret = ref->cnt;
		pthread_mutex_unlock(&ref->lock);
	}
	return (ret);
}

/** @brief Size requested for data.
  * @note the size of the data is returned.
  * @param data Pointer to data to obtain size of.
  * @returns size requested for allocation not allocation [excludes refobj].*/
extern int objsize(void *data) {
	char *ptr = data;
	int ret = 0;
	struct ref_obj *ref;

	if (!data) {
		return (ret);
	}

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj *)ptr;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(&ref->lock);
		ret = ref->size - refobj_offset;
		pthread_mutex_unlock(&ref->lock);
	}
	return (ret);
}

/** @brief Lock the reference
  * @param data Reference to lock
  * @returns Always returns 0 will only lock if a valid object.*/
extern int objlock(void *data) {
	char *ptr = data;
	struct ref_obj *ref;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj *)ptr;

	if (data && ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_lock(&ref->lock);
	}
	return (0);
}

/** @brief Try lock a reference
  * @param data Reference to attempt to lock.
  * @returns 0 on success -1 on failure.*/
extern int objtrylock(void *data) {
	char *ptr = data;
	struct ref_obj *ref;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj *)ptr;

	if (ref->magic == REFOBJ_MAGIC) {
		return ((pthread_mutex_trylock(&ref->lock)) ? -1 : 0);
	}
	return (-1);
}

/** @brief Unlock a reference
  * @param data Reference to unlock.
  * @returns Always returns 0.*/
extern int objunlock(void *data) {
	char *ptr = data;
	struct ref_obj *ref;

	ptr = ptr - refobj_offset;
	ref = (struct ref_obj *)ptr;

	if (ref->magic == REFOBJ_MAGIC) {
		pthread_mutex_unlock(&ref->lock);
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
	objunref(bloop);
}

extern void *objchar(const char *orig) {
	int len = strlen(orig) + 1;
	void *nobj;

	if ((nobj = objalloc(len, NULL))) {
		memcpy(nobj, orig, len);
	}
	return nobj;
}

/** @}
  *
  * @addtogroup LIB-OBJ-Bucket
  * @{*/

/** @brief Create a hashed bucket list.
  *
  * A bucket list is a ref obj the "list" element is a
  * array of "bucket" entries each has a hash
  * the default is to hash the memory when there is no call back
  * @todo Dont hash the memory supply a key perhaps a key array type.
  * @warning the hash must be calculated on immutable data.
  * @note a bucket list should only contain objects of the same type.
  * @note Unreferencing the bucketlist will cause it to be emptied and freed when the count reaches 0.
  * @see blisthash
  * @param bitmask Number of buckets to create 2^bitmask.
  * @param hash_function Callback that returns the unique hash for a item this value must not change.
  * @returns Reference to a empty bucket list.*/
extern void *create_bucketlist(int bitmask, blisthash hash_function) {
	struct bucket_list *new;
	short int buckets, cnt;

	buckets = (1 << bitmask);

	/* allocate session bucket list memory size of the struct plus a list lock and version for each bucket*/
	if (!(new = objalloc(sizeof(*new) + (sizeof(void *) + sizeof(pthread_mutex_t) + sizeof(size_t)) * buckets, empty_buckets))) {
		return NULL;
	}

	/*initialise each bucket*/
	new->bucketbits = bitmask;
	new->list = (void *)((char *)new + sizeof(*new));
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
	ref = (struct ref_obj *)ptr;

	if (blist->hash_func) {
		hash = blist->hash_func(data, key);
	} else if (ref && (ref->magic == REFOBJ_MAGIC)) {
		hash = jenhash(ref, ref->size, 0);
	}
	return (hash);
}

/** @brief Add a reference to the bucketlist
  *
  * Create a entry in the list for reference obtained from data.
  * @param blist Bucket list to add too.
  * @param data to obtain a reference too and add to the list.
  * @returns 0 on failure 1 on success.*/
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
	ref = (struct ref_obj *)ptr;

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

/** @brief Remove and unreference a item from the list.
  * @note Dont use this function directly during iteration as it imposes performance penalties.
  * @param blist Bucket list to remove item from.
  * @see remove_bucket_loop
  * @param data Reference to be removed and unreferenced.*/
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
		objlock(blist);
		blist->count--;
		blist->version[bucket]++;
		objunlock(blist);
	}
	pthread_mutex_unlock(&blist->locks[bucket]);
}

/** @brief Return number of items in the list.
  * @param blist Bucket list to get count of.
  * @returns Total number of items in all buckets.*/
extern int bucket_list_cnt(struct bucket_list *blist) {
	int ret = -1;

	if (blist) {
		objlock(blist);
		ret = blist->count;
		objunlock(blist);
	}
	return (ret);
}

/** @brief Find and return a reference to a item matching supplied key.
  *
  * The key is supplied to the hash callback ad the data value and the key flag set.
  * The hash for the object will be returned by the hash callback to find the item
  * in the lists.
  * @note if the hash is not calculated equal to the original value it wont be found.
  * @param blist Bucket list to search.
  * @param key Supplied to hash callback to find the item.
  * @returns New reference to the found item that needs to be unreferenced or NULL.*/
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
	} else
		if (!entry) {
			pthread_mutex_unlock(&blist->locks[bucket]);
			return NULL;
		}

	pthread_mutex_unlock(&blist->locks[bucket]);

	if (entry->data && (entry->hash == hash)) {
		return (entry->data->data);
	} else
		if (entry->data) {
			objunref(entry->data->data);
		}

	return NULL;
}

/** @brief Run a callback function on all items in the list.
  *
  * This will iterate safely through all items calling the callback with the item and the
  * optional data supplied.
  * @see blist_cb
  * @param blist Bucket list to iterate through.
  * @param callback Callback to call for each iteration.
  * @param data2 Data to be set as option to the callback.*/
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
	objunref(bloop);
}

static void free_bloop(void *data) {
	struct bucket_loop *bloop = data;

	if (bloop->blist) {
		objunref(bloop->blist);
	}
}

/** @brief Create a bucket list iterator to safely iterate the list.
  * @param blist Bucket list to create iterator for.
  * @returns Bucket list iterator that needs to be unreferenced when completed.*/
extern struct bucket_loop *init_bucket_loop(struct bucket_list *blist) {
	struct bucket_loop *bloop = NULL;

	if (blist && (bloop = objalloc(sizeof(*bloop), free_bloop))) {
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

/** @brief Return a reference to the next item in the list this could be the first item
  * @param bloop Bucket iterator
  * @returns Next available item or NULL when there no items left*/
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


/** @brief Safely remove a item from a list while iterating in a loop.
  *
  * While traversing the bucket list its best to use this function to 
  * remove a reference and delete it from the list.
  * @note Removeing a item from the list without using this function will cause the
  * the version to change and the iterator to rewind and fast forward.
  * @param bloop Bucket iterator.*/
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

/** @}*/
