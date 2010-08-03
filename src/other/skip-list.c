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
 * @param level
 * @param key
 * @param value
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
/* Public functions          					                              */
/*----------------------------------------------------------------------------*/

skip_list *skip_create_list( int (*compare_keys)(void *, void *),
							 int (*merge_values)(void *, void *)  )
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
	ss->merge_values = merge_values;

    return ss;
}

/*----------------------------------------------------------------------------*/

void *skip_find( skip_list *list, void *key )
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

int skip_insert( skip_list *list, void *key, void *value )
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
		if (list->merge_values != NULL) {	// if merge function provided, merge
			return (list->merge_values(x->value, value) == 0) ? 1 : -2;
		} else {
			return 2;
		}
	}
}

/*----------------------------------------------------------------------------*/

void skip_delete( skip_list *list, void *key )
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


	if (list->compare_keys(x->forward[i]->key, key) == 0) {
		for(i = 0; i <= list->level; i++) {
			if(update[i]->forward[i] != x) {
				break;
			}
			update[i]->forward[i] = x->forward[i];
		}

        free(x);
		while (list->level > 0 && list->head->forward[list->level] == NULL) {
			list->level--;
		}
    }
}
