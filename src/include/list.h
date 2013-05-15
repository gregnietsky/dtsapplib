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

/*
 * simple linked list struct any struct can be used
 * a more productive approach will be to include a
 * hash for searching perhaps used as a mask to array of lists
 */

#ifndef _FW_LIST_H
#define _FW_LIST_H

struct linkedlist {
	void 	*data;
	struct linkedlist *next;
	struct linkedlist *prev;
};

struct hashedlist {
	void	*data;
	int	hash;
	struct hashedlist *next;
	struct hashedlist *prev;
};

/* Initialise a list head sructure
 * malloc a chunk of data and init it
 * sets next to NULL;
 * sets prev to itself
 * list data can be NULL
 */

#define LIST_INIT(head, entry) { \
	if (!head && (!(head = malloc(sizeof(*head))))) { \
		printf("Could not allocate memory for list head\n"); \
	} else { \
		head->data = entry; \
		head->next = NULL; \
		head->prev = (entry) ? head : NULL; \
	} \
}

/*
 * Add a element to a list head struct
 * adds entry to tail
 */
#define LIST_ADD(head, entry) { \
	__typeof(head) _tmp_head = head; \
	if (!_tmp_head) { \
		LIST_INIT(_tmp_head, entry) \
		head = _tmp_head; \
	} else if (_tmp_head->prev) {\
		__typeof(head) _ent_head = NULL; \
		LIST_INIT(_ent_head, entry) \
		if (_ent_head) { \
			_ent_head->prev = _tmp_head->prev; \
			_tmp_head->prev->next = _ent_head; \
			_tmp_head->prev = _ent_head; \
		} \
	} else { \
		_tmp_head->data = entry; \
		_tmp_head->next = NULL; \
		_tmp_head->prev = _tmp_head; \
	} \
}

#define LIST_ADD_HASH(head, entry, bhash) { \
	LIST_ADD(head, entry); \
	if (head->prev->data == entry) { \
		head->hash = bhash; \
	} \
}

/*
 * Loop through a loop forward
 * it is safe to delete items in the loop
 */
#define LIST_FORLOOP(head, entry, cur) \
	for(cur = head; (cur && (entry = cur->data)); cur = cur->next)

#define LIST_FORLOOP_SAFE(head, entry, cur, tmp) \
	for(cur = head; (cur && (entry = cur->data) && ((tmp = cur->next) || 1)); cur = tmp)

#define LIST_REMOVE_ENTRY(head, cur) { \
	if (cur && (head == cur)) { \
		cur->prev->next = NULL; \
		if (cur->next) { \
			cur->next->prev = cur->prev; \
		} \
		head = cur->next; \
		free(cur); \
	} else if (cur->next) { \
		cur->prev->next = cur->next; \
		cur->next->prev = cur->prev; \
		free(cur); \
	} else { \
		cur->prev->next = NULL; \
		head->prev = cur->prev; \
		free(cur); \
	} \
}

/*
 * remove item from list
 * convinent routine to delete a item in list
 * it forwards and deletes when found
 */
#define LIST_REMOVE_ITEM(head, entry) {\
	__typeof(head) _tmp_head, _cur_head; \
	__typeof(entry) _tmp_ent; \
	LIST_FORLOOP_SAFE(head, _tmp_ent, _cur_head, _tmp_head) { \
		if (entry == _tmp_ent) { \
			LIST_REMOVE_ENTRY(head, _cur_head); \
			break; \
		} \
	} \
}

/*
 * the following macros are convinience macros
 * eliminate the need to worry about the list struct
 * only deal with the data
 */
#define LIST_FOREACH_START_SAFE(head, entry) { \
	__typeof(head) _tmp_head, _cur_head; \
	LIST_FORLOOP_SAFE(head, entry, _cur_head, _tmp_head)

#define LIST_FOREACH_START(head, entry) { \
	__typeof(head) _cur_head; \
	LIST_FORLOOP(head, entry, _cur_head)

#define LIST_FOREACH_END }

#define LIST_REMOVE_CURRENT(head) LIST_REMOVE_ENTRY(head, _cur_head)

#endif
