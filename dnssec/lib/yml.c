#include <stdbool.h>
#include <yaml.h>
#include <string.h>

#include "error.h"
#include "shared.h"
#include "yml.h"

#define _cleanup_parser_ _cleanup_(yaml_parser_delete)

/* -- internal functions --------------------------------------------------- */

/*!
 * Parse a node of expected type.
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
	yaml_node_t *found;
} mapping_find_data_t;

static int mapping_find_cb(yaml_document_t *document, dnssec_binary_t *key,
			   yaml_node_t *node, void *_data)
{
	mapping_find_data_t *data = _data;

	if (dnssec_binary_cmp(key, data->label)) {
		data->found = node;
		return DNSSEC_EOK_INTERRUPT;
	}

	return DNSSEC_EOK;
}

/*!
 * Find a value (node) for a given key (scalar) in a YAML mapping.
 */
static yaml_node_t *mapping_find(yaml_document_t *document, yaml_node_t *mapping,
				 const dnssec_binary_t *label)
{
	mapping_find_data_t data = { .label = label };

	int result = yml_mapping_each(document, mapping, mapping_find_cb, &data);
	if (result != DNSSEC_EOK) {
		return NULL;
	}

	return data.found;
}

/* -- internal API --------------------------------------------------------- */

/*!
 * Parse YAML file and return instance of parsed document.
 */
int yml_parse_file(const char *filename, yaml_document_t *document)
{
	if (!filename) {
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

	if (!yaml_parser_load(&parser, document)) {
		return DNSSEC_MALFORMED_DATA;
	}

	if (!parse_and_expect(&parser, YAML_STREAM_END_TOKEN)) {
		yaml_document_delete(document);
		return DNSSEC_MALFORMED_DATA;
	}

	return DNSSEC_EOK;
}

/*!
 * Traverse over the parsed YAML document.
 */
yaml_node_t *yml_traverse(yaml_document_t *document, yaml_node_t *from,
			  const char *path)
{
	if (!document || !from || !path) {
		return NULL;
	}

	yaml_node_t *node = from;
	const char *label = path;

	while (node && *label != '\0') {
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
		if (from->type != YAML_MAPPING_NODE) {
			return NULL;
		}

		// walk
		dnssec_binary_t bin_label = { .size = label_size,
					      .data = (uint8_t *)label };
		node = mapping_find(document, node, &bin_label);
		label = next_label;
	}

	return node;
}

/*!
 * Get value stored in a scalar node (as a reference).
 */
int yml_get_value(yaml_node_t *node, dnssec_binary_t *data)
{
	if (!node || !data) {
		return DNSSEC_EINVAL;
	}

	if (node->type != YAML_SCALAR_NODE) {
		return DNSSEC_EINVAL;
	}

	data->data = node->data.scalar.value;
	data->size = node->data.scalar.length;

	return DNSSEC_EOK;
}

/*!
 * Get string stored in a scalar node (as a copy).
 */
char *yml_get_string(yaml_node_t *node)
{
	dnssec_binary_t binary = { 0 };
	int r = yml_get_value(node, &binary);
	if (r != DNSSEC_EOK || binary.size == 0) {
		return NULL;
	}

	return strndup((char *)binary.data, binary.size);
}

/*!
 * Run a callback for each node in a sequence.
 */
int yml_sequence_each(yaml_document_t *document, yaml_node_t *sequence,
		      yml_sequence_cb callback, void *data)
{
	if (!document || !sequence || !callback) {
		return DNSSEC_EINVAL;
	}

	if (sequence->type != YAML_SEQUENCE_NODE) {
		return DNSSEC_EINVAL;
	}

	yaml_node_item_t *start = sequence->data.sequence.items.start;
	yaml_node_item_t *top = sequence->data.sequence.items.top;
	for (yaml_node_item_t *item = start; item < top; item++) {
		yaml_node_t *value = yaml_document_get_node(document, *item);
		if (!value) {
			return DNSSEC_MALFORMED_DATA;
		}

		int result = callback(document, value, data);
		if (result == DNSSEC_EOK_INTERRUPT) {
			return DNSSEC_EOK;
		} else if (result != DNSSEC_EOK) {
			return result;
		}
	}

	return DNSSEC_EOK;
}

/*!
 * Run a callback for each key-value pair in a mapping.
 */
int yml_mapping_each(yaml_document_t *document, yaml_node_t *mapping,
		     yml_mapping_cb callback, void *data)
{
	if (!document || !mapping || !callback) {
		return DNSSEC_EINVAL;
	}

	if (mapping->type != YAML_MAPPING_NODE) {
		return DNSSEC_EINVAL;
	}

	yaml_node_pair_t *start = mapping->data.mapping.pairs.start;
	yaml_node_pair_t *top = mapping->data.mapping.pairs.top;
	for (yaml_node_pair_t *pair = start; pair < top; pair++) {
		yaml_node_t *key = yaml_document_get_node(document, pair->key);
		yaml_node_t *value = yaml_document_get_node(document, pair->value);
		if (!key || !value || key->type != YAML_SCALAR_NODE) {
			return DNSSEC_MALFORMED_DATA;
		}

		dnssec_binary_t bin_key = {
			.size = key->data.scalar.length,
			.data = key->data.scalar.value
		};

		int result = callback(document, &bin_key, value, data);
		if (result == DNSSEC_EOK_INTERRUPT) {
			return DNSSEC_EOK;
		} else if (result != DNSSEC_EOK) {
			return result;
		}
	}

	return DNSSEC_EOK;
}
