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
 * @todo Consider passing the function pointers to the appropriate functions
 *       to save some space.
 */
typedef struct {
	/*! @brief Head of the list (with no actual key and value stored). */
	skip_node *head;

	/*! @brief Actual maximum level of the list. */
	int level;

	/*! @brief Function for comparing two skip list item's keys. */
	int (*compare_keys)(void *, void *);

	/*! @brief Function for merging two skip list item's values. */
	int (*merge_values)(void **, void **);

	/*! @brief Function for printing the key-value pair. */
	void (*print_item)(void *, void *);
} skip_list;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Creates a new generic skip list.
 *
 * @param compare_keys Function for comparing the keys.
 * @param merge_values Function for merging the saved values. Optional. If set
 *                     to NULL, the skip list will not merge values when
 *                     attempting to insert item with key already present in the
 *                     list.
 * @param print_item Function for printing the key-value pair. Optional. If set
 *                   to NULL, the skip_print_list() will output nothing.
 *
 * The @a merge_values function should  merge the second value to the first
 * value. It must not delete the first value. The second value also should not
 * be deleted (as this is concern of the caller).
 *
 * @return Pointer to the newly created skip list if successful. NULL otherwise.
 */
skip_list *skip_create_list( int (*compare_keys)(void *, void *),
							 int (*merge_values)(void **, void **),
							 void (*print_item)(void *, void *) );

/*!
 * @brief Properly destroys the list, possibly also with the keys and values.
 *
 * @param list Skip list to be destroyed.
 * @param destroy_key Function for properly destroying the key. If set tu NULL,
 *                    the object at which the key points will not be destroyed.
 * @param destroy_value Function for properly destroying the key. If set tu
 *                      NULL, the object at which the value points will not be
 *                      destroyed.
 */
void skip_destroy_list( skip_list *list, void (*destroy_key)(void *),
						void (*destroy_value)(void *));

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
 * @retval 1 If the key was already present and the new value was ignored
 *           (because no merging function was provided).
 * @retval 2 If successful, the key was already present and the values were
 *           merged.
 * @retval -1 If an error occured and the key was not present in the list.
 * @retval -2 If the key is already present in the list and merging was
 *            unsuccessful.
 */
int skip_insert( skip_list *list, void *key, void *value );

/*!
 * @brief Removes an item with the given key from the list and optionally
 *        deletes the item's key and value.
 *
 * @param list Skip list to delete from.
 * @param key Key of the item to be deleted.
 * @param destroy_key Function for properly destroying the key. If set tu NULL,
 *                    the object at which the key points will not be destroyed.
 * @param destroy_value Function for properly destroying the key. If set tu
 *                      NULL, the object at which the value points will not be
 *                      destroyed.
 *
 * @retval 0 If successful.
 * @retval -1 If the item was not present in the list.
 */
int skip_remove( skip_list *list, void *key, void (*destroy_key)(void *),
				  void (*destroy_value)(void *) );

/*!
 * @brief Tries to find item with the given key in the list.
 *
 * @param list Skip list to search in.
 * @param key Key of the item to be found.
 *
 * @return Value stored in the item with key @a key, or NULL if the key was not
 *         found.
 */
void *skip_find( const skip_list *list, void *key );

/*!
 * @brief Prints the whole list to standard output.
 *
 * @param list Skip list to be printed.
 *
 * The list must have had the print_item set when it was created. Otherwise this
 * function will output nothing.
 */
void skip_print_list( const skip_list *list );
