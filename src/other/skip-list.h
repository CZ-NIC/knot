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

/*----------------------------------------------------------------------------*/
/*!
 * @brief Skip list node.
 */
struct skip_node {
	/*! @brief Key of the node. Used for ordering. */
	void *key;

	/*! @brief Value stored in the node. */
	void *value;

	/*! @brief Pointers to next item on various levels. */
	struct skip_node **forward;
};

typedef struct skip_node skip_node;

/*!
 * @brief Skip list.
 *
 * @todo Implement quasi-randomization.
 */
typedef struct {
	/*! @brief Head of the list (with no actual key and value stored). */
	skip_node *head;

	/*! @brief Actual maximum level of the list. */
	int level;

	/*! @brief Function for comparing two skip list item's keys. */
	int (*compare_keys)(void *, void *);

	/*! @brief Function for merging two skip list item's values. */
	int (*merge_values)(void *, void *);
} skip_list;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Creates a new generic skip list.
 *
 * @param compare_keys Pointer to a function for comparing the keys.
 * @param merge_values Pointer to a function for merging the saved values.
 *
 * Parameter @a merge_values is optional. If set to NULL, the skip list will not
 * merge values when attempting to insert item with key already present in the
 * list.
 *
 * The @a merge_values function should merge the second value to the first
 * value. It must not delete the first value. The second value also should not
 * be deleted (as this is concern of the caller).
 *
 * @return Pointer to the newly created skip list if successful. NULL otherwise.
 */
skip_list *skip_create_list( int (*compare_keys)(void *, void *),
							 int (*merge_values)(void *, void *) );

/*!
 * @brief Inserts a new key-value pair into the skip list.
 *
 * @param list The skip list to insert to.
 * @param key Key of the item to be inserted. Used for ordering.
 * @param value Value of the item to be inserted.
 *
 * If a merge function was specified upon creation of the list and @a key is
 * already present in the list, the new value will be merged to the value saved
 * in the list node. Otherwise the function does nothing.
 *
 * @retval 0 If successful and the key was not yet present in the list.
 * @retval 1 If successful, the key was already present and the values were
 *           merged.
 * @retval 2 If the key was already present and the new value was ignored (because
 *           no merging function was provided).
 * @retval -1 If an error occured and the key was not present in the list.
 * @retval -2 If the key is already present in the list and merging was
 *            unsuccessful.
 */
int skip_insert( skip_list *list, void *key, void *value );

/*!
 * @brief Deletes an item with the given key from the list.
 *
 * @param list Skip list to delete from.
 * @param key Key of the item to be deleted.
 */
void skip_delete( skip_list *list, void *key );

/*!
 * @brief Tries to find item with the given key in the list.
 *
 * @param list Skip list to search in.
 * @param key Key of the item to be found.
 *
 * @return Value stored in the item with key @a key, or NULL if the key was not
 *         found.
 */
void *skip_find( skip_list *list, void *key );
