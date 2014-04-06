#pragma once

#include <stdbool.h>
#include <yaml.h>

#include "binary.h"

#define YML_PATH_SEPARATOR '/'
#define DNSSEC_EOK_INTERRUPT (DNSSEC_EOK + 1)

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
int yml_parse_file(const char *filename, yaml_document_t *document);

/*!
 * Traverse over the parsed YAML document.
 *
 * Traversable nodes have \ref YAML_MAPPING_NODE type.
 *
 * \param document  Document into which the starting node belongs.
 * \param from      Starting node.
 * \param path      Path to the target node, components are separated by '/'.
 *
 * \return Target node, or NULL if the path does not exist.
 */
yaml_node_t *yml_traverse(yaml_document_t *document, yaml_node_t *from,
			  const char *path);

/*!
 * Get value stored in a scalar node (as a reference).
 *
 * \param[in]  node  Scalar node.
 * \param[out] data  Reference to data within the node.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int yml_get_value(yaml_node_t *node, dnssec_binary_t *data);

/*!
 * Get string stored in a scalar node (as a copy).
 *
 * \param node  Scalar node.
 *
 * \return Copy of the string
 *
 */
char *yml_get_string(yaml_node_t *node);

/*!
 * Callback parameter for \ref yml_sequence_each.
 */
typedef int (*yml_sequence_cb)(yaml_document_t *document, yaml_node_t *item, void *data);

/*!
 * Run a callback for each node in a sequence.
 *
 * \param document  Associated document.
 * \param sequence  Sequence to be iterated.
 * \param callback  Callback function to be called for each item in the sequence.
 * \param data      Custom data passed to the callback function.
 *
 * \return Error code, DNSSEC_EOK if successful. A failure in a callback
 *         function is propagated and the iteration is interrupted. If the
 *         callback function returns DNSSEC_EOK_INTERRUPT, the iteration is
 *         interrupted, but DNSSEC_EOK is returned.
 */
int yml_sequence_each(yaml_document_t *document, yaml_node_t *sequence,
		      yml_sequence_cb callback, void *data);

typedef int (*yml_mapping_cb)(yaml_document_t *document, dnssec_binary_t *key,
			      yaml_node_t *value, void *data);

/*!
 * Run a callback for each key-value pair in a mapping.
 *
 * Parameters and semantic are the same as for \ref yml_sequence_each.
 */
int yml_mapping_each(yaml_document_t *document, yaml_node_t *mapping,
		     yml_mapping_cb callback, void *data);
