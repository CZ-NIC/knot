#include <stdbool.h>
#include <yaml.h>
#include <string.h>

#include "error.h"
#include "shared.h"
#include "yml.h"

#define _cleanup_parser_ _cleanup_(yaml_parser_delete)

/* -- internal functions --------------------------------------------------- */

/*!
 * Parse a node of expected type and drop it.
 */
static bool parse_and_expect(yaml_parser_t *parser, int type)
{
	yaml_event_t event = { 0 };
	if (!yaml_parser_parse(parser, &event)) {
		return false;
	}

	int event_type = event.type;
	yaml_event_delete(&event);

	return event_type == type;
}

typedef struct {
	const dnssec_binary_t *label;
	yml_node_t found;
} mapping_find_data_t;

static int mapping_find_cb(dnssec_binary_t *key, yml_node_t *value,
			   void *_data, bool *interrupt)
{
	mapping_find_data_t *data = _data;

	if (dnssec_binary_cmp(key, data->label) == 0) {
		data->found = *value;
		*interrupt = true;
	}

	return DNSSEC_EOK;
}

/*!
 * Find a value (node) for a given key (scalar) in a YAML mapping.
 */
static int mapping_find(yml_node_t *mapping, const dnssec_binary_t *label,
			yml_node_t *result)
{
	mapping_find_data_t data = { .label = label };

	int r = yml_mapping_each(mapping, mapping_find_cb, &data);
	if (r != DNSSEC_EOK) {
		return r;
	}

	if (data.found.node == NULL) {
		return DNSSEC_NOT_FOUND;
	}

	*result = data.found;

	return DNSSEC_EOK;
}

/* -- internal API --------------------------------------------------------- */

int yml_node_init(yml_node_t *node)
{
	if (!node) {
		return DNSSEC_EINVAL;
	}

	clear_struct(node);
	node->document = calloc(1, sizeof(yaml_document_t));
	if (!node->document) {
		return DNSSEC_ENOMEM;
	}

	return DNSSEC_EOK;
}

void yml_node_deinit(yml_node_t *node)
{
	if (!node) {
		return;
	}

	if (node->document) {
		yaml_document_delete(node->document);
		free(node->document);
	}

	clear_struct(node);
}

/*!
 * Parse YAML file and return instance of parsed document.
 */
int yml_parse_file(const char *filename, yml_node_t *root)
{
	if (!filename || !root) {
		return DNSSEC_EINVAL;
	}

	_cleanup_fclose_ FILE *file = fopen(filename, "r");
	if (!file) {
		return dnssec_errno_to_error(errno);
	}

	// initialize parser

	_cleanup_parser_ yaml_parser_t parser = {0};
	if (!yaml_parser_initialize(&parser)) {
		return DNSSEC_ENOMEM;
	}
	yaml_parser_set_input_file(&parser, file);

	// parse content

	if (!parse_and_expect(&parser, YAML_STREAM_START_TOKEN)) {
		return DNSSEC_MALFORMED_DATA;
	}

	yaml_document_t document;
	if (!yaml_parser_load(&parser, &document)) {
		return DNSSEC_MALFORMED_DATA;
	}

	if (!parse_and_expect(&parser, YAML_STREAM_END_TOKEN)) {
		yaml_document_delete(&document);
		return DNSSEC_MALFORMED_DATA;
	}

	// finalize

	int result = yml_node_init(root);
	if (result != DNSSEC_EOK) {
		yaml_document_delete(&document);
		return result;
	}

	*root->document = document;
	root->node = yaml_document_get_root_node(root->document);

	return DNSSEC_EOK;
}

/*!
 * Traverse over the parsed YAML document.
 */
int yml_traverse(yml_node_t *from, const char *path, yml_node_t *to)
{
	if (!from || !path || !to) {
		return DNSSEC_EINVAL;
	}

	yml_node_t node = *from;
	const char *label = path;

	while (*label != '\0') {
		// find next label
		size_t label_size = 0;
		const char *next_label = strchr(label, YML_PATH_SEPARATOR);
		if (next_label == NULL) {
			label_size = strlen(label);
			next_label = label + label_size;
		} else {
			label_size = next_label - label;
			next_label += 1;
		}

		// non walkable nodes
		if (node.node->type != YAML_MAPPING_NODE) {
			return DNSSEC_EINVAL;
		}

		// walk
		yml_node_t next;
		dnssec_binary_t bin_label = {
			.size = label_size,
			.data = (uint8_t *)label
		};
		int r = mapping_find(&node, &bin_label, &next);
		if (r != DNSSEC_EOK) {
			return r;
		}

		node = next;
		label = next_label;
	}

	*to = node;
	return DNSSEC_EOK;
}

/*!
 * Traverse from the node, updating the node itself.
 */
static int self_traverse(yml_node_t *node, const char *path)
{
	assert(node);

	if (!path) {
		return DNSSEC_EOK;
	}

	yml_node_t new_node = { 0 };
	int result = yml_traverse(node, path, &new_node);
	if (result != DNSSEC_EOK) {
		return result;
	}

	*node = new_node;
	return DNSSEC_EOK;
}

/*!
 * Get value stored in a scalar node (as a reference).
 */
int yml_get_value(yml_node_t *node, const char *path, dnssec_binary_t *data)
{
	if (!node || !data) {
		return DNSSEC_EINVAL;
	}

	yml_node_t target = *node;
	int result = self_traverse(&target, path);
	if (result != DNSSEC_EOK) {
		return result;
	}

	if (target.node->type != YAML_SCALAR_NODE) {
		return DNSSEC_EINVAL;
	}

	data->data = target.node->data.scalar.value;
	data->size = target.node->data.scalar.length;

	return DNSSEC_EOK;
}

/*!
 * Get string stored in a scalar node (as a copy).
 */
char *yml_get_string(yml_node_t *node, const char *path)
{
	dnssec_binary_t binary = { 0 };
	int r = yml_get_value(node, path, &binary);
	if (r != DNSSEC_EOK || binary.size == 0) {
		return NULL;
	}

	return strndup((char *)binary.data, binary.size);
}

/*!
 * Run a callback for each node in a sequence.
 */
int yml_sequence_each(yml_node_t *sequence, yml_sequence_cb callback, void *data)
{
	if (!sequence || !callback) {
		return DNSSEC_EINVAL;
	}

	if (sequence->node->type != YAML_SEQUENCE_NODE) {
		return DNSSEC_EINVAL;
	}

	yaml_document_t *doc = sequence->document;
	yml_node_t value = { .document = doc };

	yaml_node_item_t *start = sequence->node->data.sequence.items.start;
	yaml_node_item_t *top = sequence->node->data.sequence.items.top;
	for (yaml_node_item_t *item = start; item < top; item++) {
		// get value
		value.node = yaml_document_get_node(doc, *item);
		if (!value.node) {
			return DNSSEC_MALFORMED_DATA;
		}
		// run callback
		bool interrupt = false;
		int result = callback(&value, data, &interrupt);
		if (result != DNSSEC_EOK || interrupt) {
			return result;
		}
	}

	return DNSSEC_EOK;
}

/*!
 * Run a callback for each key-value pair in a mapping.
 */
int yml_mapping_each(yml_node_t *mapping, yml_mapping_cb callback, void *data)
{
	if (!mapping || !callback) {
		return DNSSEC_EINVAL;
	}

	if (mapping->node->type != YAML_MAPPING_NODE) {
		return DNSSEC_EINVAL;
	}

	yaml_document_t *doc = mapping->document;
	yml_node_t value = { .document = doc };

	yaml_node_pair_t *start = mapping->node->data.mapping.pairs.start;
	yaml_node_pair_t *top = mapping->node->data.mapping.pairs.top;
	for (yaml_node_pair_t *pair = start; pair < top; pair++) {
		// get key and value nodes
		yaml_node_t *key = yaml_document_get_node(doc, pair->key);
		if (!key|| key->type != YAML_SCALAR_NODE) {
			return DNSSEC_MALFORMED_DATA;
		}
		value.node = yaml_document_get_node(doc, pair->value);
		if (!value.node) {
			return DNSSEC_MALFORMED_DATA;
		}
		// wrap key into binary
		dnssec_binary_t bin_key = {
			.size = key->data.scalar.length,
			.data = key->data.scalar.value
		};
		// run callback
		bool interrupt = false;
		int result = callback(&bin_key, &value, data, &interrupt);
		if (result != DNSSEC_EOK || interrupt) {
			return result;
		}
	}

	return DNSSEC_EOK;
}
