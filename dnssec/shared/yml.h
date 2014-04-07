#pragma once

#include <stdbool.h>
#include <yaml.h>

#include "binary.h"
#include "shared.h"

#define YML_PATH_SEPARATOR '/'

#define _cleanup_yml_node_ _cleanup_(yml_node_deinit)

typedef struct yml_node {
	yaml_document_t *document;
	yaml_node_t *node;
} yml_node_t;

int yml_node_init(yml_node_t *node);
void yml_node_deinit(yml_node_t *node);

/*!
 * Parse YAML file and return an instance of parsed document.
 *
 * Does not support multiple documents within one YAML stream.
 *
 * \param[in]  filename  File to be parsed.
 * \param[out] document  Parsed document. Must be destoryed with
 *                       \ref yaml_document_destroy (libyaml).
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int yml_parse_file(const char *filename, yml_node_t *root);

/*!
 * Traverse over the parsed YAML document.
 *
 * Only nodes of type \ref YAML_MAPPING_NODE can be traversed.
 *
 * \param[in]  from  Search start node.
 * \param[in]  path  Path to the target node, components are separated by '/'.
 * \param[out] to    Node found by traversal.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int yml_traverse(yml_node_t *from, const char *path, yml_node_t *to);

/*!
 * Get value stored in a scalar node (as a reference).
 *
 * \param[in]  node  Scalar node.
 * \param[in]  path  Optional path to perform traverse before retrieving value.
 * \param[out] data  Reference to data within the node.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int yml_get_value(yml_node_t *node, const char *path, dnssec_binary_t *data);

/*!
 * Get string stored in a scalar node (as a copy).
 *
 * \param node  Scalar node.
 * \param path  Optional path to perform traverse before retrieving value.
 *
 * \return Copy of the string, NULL in case of error.
 */
char *yml_get_string(yml_node_t *node, const char *path);

/*!
 * Callback parameter for \ref yml_sequence_each.
 */
typedef int (*yml_sequence_cb)(yml_node_t *item, void *data, bool *interrupt);

/*!
 * Run a callback for each node in a sequence.
 *
 * \param sequence  Sequence to be iterated.
 * \param callback  Callback function to be called for each item in the sequence.
 * \param data      Custom data passed to the callback function.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int yml_sequence_each(yml_node_t *sequence, yml_sequence_cb callback, void *data);

typedef int (*yml_mapping_cb)(dnssec_binary_t *key, yml_node_t *value, void *data,
			      bool *interrupt);

/*!
 * Run a callback for each key-value pair in a mapping.
 *
 * Parameters and semantic are the same as for \ref yml_sequence_each.
 */
int yml_mapping_each(yml_node_t *mapping, yml_mapping_cb callback, void *data);
