#pragma once
/*
 *	ncc_dlist.h
 */

#include <freeradius-devel/server/base.h>

/*
 *	Chained list using FreeRADIUS "dlist.h" (which do not require the chaining data to be stored first).
 *	Handle current list size.
 *	Provides utility macros.
 */
typedef struct ncc_dlist {
	fr_dlist_head_t head;
	uint32_t size;
	bool init;

	void *last_used;        //< Last item used with "NCC_DLIST_USE_NEXT".
} ncc_dlist_t;

/*
 *	Get list current size.
 */
#define NCC_DLIST_SIZE(_ncc_dlist) ((*_ncc_dlist).size)

/*
 *	Iterate on a list, starting from head.
 */
#define NCC_DLIST_HEAD(_ncc_dlist) fr_dlist_head(&(*_ncc_dlist).head);
#define NCC_DLIST_TAIL(_ncc_dlist) fr_dlist_tail(&(*_ncc_dlist).head);
#define NCC_DLIST_NEXT(_ncc_dlist, _item) fr_dlist_next(&(*_ncc_dlist).head, _item);

#define NCC_DLIST_IS_INIT(_ncc_dlist) (*_ncc_dlist).init

/*
 *	An item does not belong to a list if it's linked to itself.
 */
#define NCC_IS_LONE_ITEM(_item) \
	(_item->dlist.prev == &(_item->dlist) && _item->dlist.next == &(_item->dlist))

/*
 *	Initialize a list of "_item_struct_t" containing a chaining struct "fr_dlist_t dlist".
 */
#define NCC_DLIST_INIT(_ncc_dlist, _item_struct_t) { \
	if (!NCC_DLIST_IS_INIT(_ncc_dlist)) { \
		fr_dlist_init(&((*_ncc_dlist).head), _item_struct_t, dlist); \
		(*_ncc_dlist).size = 0; \
		(*_ncc_dlist).init = true; \
	} \
}

/*
 *	Allocate a new list item and properly initialize it.
 *	An item should be initialized ("prev == item && next == item")
 *	... although it doesn't really matter if the item is immediately inserted in the list.
 */
#define NCC_DLIST_ALLOC_ITEM(_ctx, _item, _item_struct_t) { \
	_item = talloc_zero(_ctx, _item_struct_t); \
	if (_item) fr_dlist_entry_init(&(_item->dlist)); \
}

/*
 *	Remove an item from its list.
 *	Does nothing if it's not in list.
 *	Clear "last used" if this is the item removed. Ensures we do not access freed memory later on.
 */
#define NCC_DLIST_REMOVE(_ncc_dlist, _item) { \
	if (_item && !NCC_IS_LONE_ITEM(_item)) { \
		fr_dlist_head_t *list_head = &(*_ncc_dlist).head; \
		if (_item == (*_ncc_dlist).last_used) (*_ncc_dlist).last_used = NULL; \
		fr_dlist_remove(list_head, _item); \
		(*_ncc_dlist).size--; \
	} \
}

// this is now just the same so...
#define NCC_DLIST_DRAW(_ncc_dlist, _item) NCC_DLIST_REMOVE(_ncc_dlist, _item)

/*
 *	Add an item to the tail of the list.
 */
#define NCC_DLIST_ENQUEUE(_ncc_dlist, _item) { \
	if (_item) { \
		fr_dlist_insert_tail(&(*_ncc_dlist).head, _item); \
		(*_ncc_dlist).size++; \
	} \
}

/*
 *	Add an item to the head of the list.
 */
#define NCC_DLIST_PUSH(_ncc_dlist, _item) { \
	if (_item) { \
		fr_dlist_insert_head(&(*_ncc_dlist).head, _item); \
		(*_ncc_dlist).size++; \
	} \
}

/*
 *	Get (and remove) the head item from a list.
 */
#define NCC_DLIST_DEQUEUE(_ncc_dlist, _item) { \
	fr_dlist_head_t *list_head = &(*_ncc_dlist).head; \
	_item = fr_dlist_head(list_head); \
	if (_item) { \
		NCC_DLIST_REMOVE(_ncc_dlist, _item); \
	} \
}

/*
 *	Remove all items from list.
 */
#define NCC_DLIST_CLEAR(_ncc_dlist, _item) { \
	fr_dlist_head_t *list_head = &(*_ncc_dlist).head; \
	_item = NULL; \
	while ((_item = fr_dlist_next(list_head, _item))) { \
		_item = fr_dlist_remove(list_head, _item); \
	} \
	(*_ncc_dlist).size = 0; \
	(*_ncc_dlist).last_used = NULL; \
}

/*
 *	Get reference on a list item from its index (position in the list, starting at 0).
 *	Item is not removed from the list.
 */
#define NCC_DLIST_INDEX(_ncc_dlist, _index, _item) { \
	fr_dlist_head_t *list_head = &(*_ncc_dlist).head; \
	_item = NULL; \
	if (_index < (*_ncc_dlist).size) { \
		int _i; \
		for (_i = 0, _item = fr_dlist_head(list_head); \
		     _i < _index && _item != NULL;  \
		     _i++, _item = fr_dlist_next(list_head, _item)) { \
		} \
	} \
}

/** Insert an item before an existing (reference) item of a list.
 */
static inline void fr_dlist_insert_before(fr_dlist_head_t *list_head, void *ptr_ref, void *ptr)
{
	fr_dlist_t *entry_ref, *entry;
	fr_dlist_t *head;

	if (!ptr) return;
	if (!ptr_ref) return;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (list_head->type) ptr = _talloc_get_type_abort(ptr, list_head->type, __location__);
#endif

	entry_ref = (fr_dlist_t *) (((uint8_t *) ptr_ref) + list_head->offset);
	entry = (fr_dlist_t *) (((uint8_t *) ptr) + list_head->offset);
	head = &(list_head->entry);

	if (!fr_cond_assert(head->next != NULL)) return;
	if (!fr_cond_assert(head->prev != NULL)) return;

	entry->next = entry_ref;
	entry->prev = entry_ref->prev;

	entry_ref->prev->next = entry;
	entry_ref->prev = entry;
}

#define NCC_DLIST_INSERT_BEFORE(_ncc_dlist, _item_ref, _item) { \
	if (_item_ref && _item) { \
		fr_dlist_head_t *list_head = &(*_ncc_dlist).head; \
		fr_dlist_insert_before(list_head, _item_ref, _item); \
		(*_ncc_dlist).size++; \
	} \
}

/* Use items from a list in a sequential circular fashion, starting from head.
 * Remember the last item used.
 * If the last item used is removed from the list then start over from head.
 */
#define NCC_DLIST_USE_NEXT(_ncc_dlist, _item) { \
	_item = (*_ncc_dlist).last_used; \
	if (!_item || NCC_IS_LONE_ITEM(_item)) { \
		_item = NCC_DLIST_HEAD(_ncc_dlist); \
	} else { \
		_item = NCC_DLIST_NEXT(_ncc_dlist, (*_ncc_dlist).last_used); \
		if (!_item) _item = NCC_DLIST_HEAD(_ncc_dlist); \
	} \
	(*_ncc_dlist).last_used = _item; \
}
