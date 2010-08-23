/* Copyright (c) 2010 the authors listed at the following URL, and/or
the authors of referenced articles or incorporated external code:
http://en.literateprograms.org/Skip_list_(C)?action=history&offset=20080313195128

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Retrieved from: http://en.literateprograms.org/Skip_list_(C)?oldid=12811
*/

/*
 * Modifications by Lubos Slovak, 2010
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "skip-list.h"
#include "common.h"

/*----------------------------------------------------------------------------*/

static const float P = 0.5;

/*!
 * @brief Maximum level of a node, i.e. maximum number of skip list levels.
 */
static const int MAX_LEVEL = 6;

/*----------------------------------------------------------------------------*/
/* Private functions          					                              */
/*----------------------------------------------------------------------------*/
/*!
 * @brief Generates random real number between 0 and 1.
 */
float frand() {
    return (float) rand() / RAND_MAX;
}

/*----------------------------------------------------------------------------*/
/*!
 * @brief Returns random level between 0 and MAX_LEVEL.
 */
int skip_random_level() {
    static int first = 1;
    int lvl = 0;

    if(first) {
        srand( (unsigned)time( NULL ) );
        first = 0;
    }

	while (frand() < P && lvl < MAX_LEVEL) {
		lvl++;
	}

    return lvl;
}

/*----------------------------------------------------------------------------*/
/*!
 * @brief Creates a new skip list node with the given key and value.
 *
 * @param level Level of the skip list node.
 * @param key Key of the new node.
 * @param value Value to be stored in the node.
 *
 * @return Pointer to the newly created node or NULL if not successful.
 */
skip_node *skip_make_node( int level, void *key, void *value )
{
	skip_node *sn = (skip_node *)malloc(sizeof(skip_node));
	if (sn == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	sn->forward = (skip_node **)calloc(level + 1, sizeof(skip_node *));
	if (sn->forward == NULL) {
		ERR_ALLOC_FAILED;
		free(sn);
		return NULL;
	}
 
	sn->key = key;
    sn->value = value;
    return sn;
}

/*----------------------------------------------------------------------------*/
/*!
 * @brief Properly deallocates the given skip list node, and optionally destroys
 *        its key and value.
 *
 * @param node Skip list node to be deleted.
 * @param destroy_key Function for properly destroying the key. If set tu NULL,
 *                    the object at which the key points will not be destroyed.
 * @param destroy_value Function for properly destroying the key. If set tu
 *                      NULL, the object at which the value points will not be
 *                      destroyed.
 */
void skip_delete_node( skip_node **node, void (*destroy_key)(void *),
				  void (*destroy_value)(void *) )
{
	if (destroy_key != NULL) {
		destroy_key((*node)->key);
	}
	if (destroy_value != NULL) {
		destroy_value((*node)->value);
	}

	free((*node)->forward);
	free(*node);

	node = NULL;
}

/*----------------------------------------------------------------------------*/
/* Public functions          					                              */
/*----------------------------------------------------------------------------*/

skip_list *skip_create_list( int (*compare_keys)(void *, void *) )
{
	assert(compare_keys != NULL);

	skip_list *ss = (skip_list *)malloc(sizeof(skip_list));
	if (ss == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ss->head = skip_make_node(MAX_LEVEL, NULL, NULL);
	if (ss->head == NULL) {
		ERR_ALLOC_FAILED;
		free(ss);
		return NULL;
	}

    ss->level = 0;
	ss->compare_keys = compare_keys;

    return ss;
}

/*----------------------------------------------------------------------------*/

void skip_destroy_list( skip_list **list, void (*destroy_key)(void *),
						void (*destroy_value)(void *))
{
	assert((*list) != NULL);
	assert((*list)->head != NULL);

	skip_node *x;

	while ((*list)->head->forward[0] != NULL) {
		x = (*list)->head->forward[0];
		for (int i = 0; i <= (*list)->level; i++) {
			if ((*list)->head->forward[i] != x) {
				break;
			}
			(*list)->head->forward[i] = x->forward[i];
		}

		// delete the item
		skip_delete_node(&x, destroy_key, destroy_value);

		while ((*list)->level > 0
			   && (*list)->head->forward[(*list)->level] == NULL) {
			(*list)->level--;
		}
	}

	// free the head
	skip_delete_node(&(*list)->head, NULL, NULL);

	free(*list);
	*list = NULL;
}

/*----------------------------------------------------------------------------*/

void *skip_find( const skip_list *list, void *key )
{
	assert(list != NULL);
	assert(list->head != NULL);
	assert(list->compare_keys != NULL);

    int i;
	skip_node *x = list->head;
	for(i = list->level; i >= 0; i--) {
		while(x->forward[i] != NULL
			  && list->compare_keys(x->forward[i]->key, key) == -1) {
            x = x->forward[i];
        }
    }
    x = x->forward[0];

	if (x != NULL && list->compare_keys(x->key, key) == 0) {
		return x->value;
	}
	return NULL;
}

/*----------------------------------------------------------------------------*/

int skip_insert( skip_list *list, void *key, void *value,
				 int (*merge_values)(void **, void **) )
{
	assert(list != NULL);
	assert(list->head != NULL);
	assert(list->compare_keys != NULL);

    int i;
	skip_node *x = list->head;
	skip_node *update[MAX_LEVEL + 1];
    memset(update, 0, MAX_LEVEL + 1);

	for (i = list->level; i >= 0; i--) {
		while (x->forward[i] != NULL
			  && list->compare_keys(x->forward[i]->key, key) == -1) {
            x = x->forward[i];
        }
        update[i] = x; 
    }
    x = x->forward[0];

	if (x == NULL || list->compare_keys(x->key, key) != 0) {
		int lvl = skip_random_level();
  
		if (lvl > list->level) {
			for (i = list->level + 1; i <= lvl; i++) {
				update[i] = list->head;
			}
			list->level = lvl;
		}

		x = skip_make_node(lvl, key, value);
		if (x == NULL) {
			ERR_ALLOC_FAILED;
			return -1;
		}

		for (i = 0; i <= lvl; i++) {
			x->forward[i] = update[i]->forward[i];
			update[i]->forward[i] = x;
		}

		return 0;
	} else {	// already in the list
		if (merge_values != NULL) {	// if merge function provided, merge
			return (merge_values(&x->value, &value) == 0) ? 2 : -2;
		} else {
			return 1;
		}
	}
}

/*----------------------------------------------------------------------------*/

int skip_remove( skip_list *list, void *key, void (*destroy_key)(void *),
				  void (*destroy_value)(void *) )
{
	assert(list != NULL);
	assert(list->head != NULL);
	assert(list->compare_keys != NULL);

    int i;
	skip_node *x = list->head;
	skip_node *update[MAX_LEVEL + 1];
    memset(update, 0, MAX_LEVEL + 1);

	for (i = list->level; i >= 0; i--) {
		while (x->forward[i] != NULL
			  && list->compare_keys(x->forward[i]->key, key) == -1) {
            x = x->forward[i];
        }
        update[i] = x; 
    }
    x = x->forward[0];

	if (x != NULL && list->compare_keys(x->key, key) == 0) {
		for (i = 0; i <= list->level; i++) {
			if (update[i]->forward[i] != x) {
				break;
			}
			update[i]->forward[i] = x->forward[i];
		}

		// delete the item
		skip_delete_node(&x, destroy_key, destroy_value);

		while (list->level > 0 && list->head->forward[list->level] == NULL) {
			list->level--;
		}
		return 0;
	} else {
		return -1;
	}
}

/*----------------------------------------------------------------------------*/

int skip_empty( const skip_list *list )
{
	return (list->head->forward[0] == NULL) ? 0 : 1;
}

/*----------------------------------------------------------------------------*/

const skip_node *skip_first( const skip_list *list )
{
	return list->head->forward[0];
}

/*----------------------------------------------------------------------------*/

const skip_node *skip_next( const skip_node *node )
{
	return node->forward[0];
}

/*----------------------------------------------------------------------------*/

void skip_print_list( const skip_list *list,
					  void (*print_item)(void *, void *) )
{
	assert(list != NULL);
	assert(list->head != NULL);
	assert(list->compare_keys != NULL);
	assert(print_item != NULL);

	skip_node *x = list->head->forward[0];
	while (x != NULL) {
		print_item(x->key, x->value);
		x = x->forward[0];
	}

}
