/** @file
  * @brief XML Interface.
  * @ingroup LIB-XML
  * @addtogroup LIB-XML
  * @{*/

#include <string.h>
#include <stdint.h>
#ifdef __WIN32__
#include <sec_api/string_s.h>
#endif

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "include/priv_xml.h"
#include "include/dtsapp.h"

/** @brief Iterator to traverse nodes in a xpath.*/
struct xml_node_iter {
	/** @brief Reference to search returned from xml_search()*/
	struct xml_search *xsearch;
	/** @brief current position.*/
	int curpos;
	/** @brief number of nodes in search path.*/
	int cnt;
};

/** @brief XML xpath search result
  * @see xml_search()*/
struct xml_search {
	/** @brief Reference to XML document.*/
	struct xml_doc *xmldoc;
	/** @brief Xpath object.*/
	xmlXPathObjectPtr xpathObj;
	/** @brief Bucket list of all nodes.*/
	struct bucket_list *nodes;
};

static void *xml_has_init_parser = NULL;

/** @brief Reference destructor for xml_buffer
  * @warning do not call this directly.*/
void xml_free_buffer(void *data) {
	struct xml_buffer *xb = data;
	xmlFree(xb->buffer);
}

static void free_xmlsearch(void *data) {
	struct xml_search *xs = data;
	objunref(xs->xmldoc);
	objunref(xs->nodes);
	xmlXPathFreeObject(xs->xpathObj);
}

static void free_parser(void *data) {
	xmlCleanupParser();
}

static void free_xmlnode(void *data) {
	struct xml_node *ninfo = data;

	if (ninfo->attrs) {
		objunref(ninfo->attrs);
	}
	if (ninfo->name) {
		free((char *)ninfo->name);
	}
	if (ninfo->key) {
		free((char *)ninfo->key);
	}
	if (ninfo->value) {
		free((char *)ninfo->value);
	}
}

static void free_xmldata(void *data) {
	struct xml_doc *xmldata = data;

	if (xmldata->xpathCtx) {
		xmlXPathFreeContext(xmldata->xpathCtx);
	}
	if (xmldata->doc) {
		xmlFreeDoc(xmldata->doc);
	}
	if (xmldata->ValidCtxt) {
		xmlFreeValidCtxt(xmldata->ValidCtxt);
	}
	xml_close();
}

static int32_t node_hash(const void *data, int key) {
	int ret;
	const struct xml_node *ni = data;
	const char *hashkey = (key) ? data : ni->key;

	if (hashkey) {
		ret = jenhash(hashkey, strlen(hashkey), 0);
	} else {
		ret = jenhash(ni, sizeof(ni), 0);
	}
	return(ret);
}

static int32_t attr_hash(const void *data, int key) {
	int ret;
	const struct xml_attr *ai = data;
	const char *hashkey = (key) ? data : ai->name;

	ret = jenhash(hashkey, strlen(hashkey), 0);

	return(ret);
}

static struct xml_doc *xml_setup_parse(struct xml_doc *xmldata, int validate) {
	if (validate) {
		if (!(xmldata->ValidCtxt = xmlNewValidCtxt())) {
			objunref(xmldata);
			return NULL;
		}
		if (!xmlValidateDocument(xmldata->ValidCtxt, xmldata->doc)) {
			objunref(xmldata);
			return NULL;
		}
		/*xmlValidateDocumentFinal(xmldata->ValidCtxt, xmldata->doc);*/
	}

	if (!(xmldata->root = xmlDocGetRootElement(xmldata->doc))) {
		objunref(xmldata);
		return NULL;
	}

	if (!(xmldata->xpathCtx = xmlXPathNewContext(xmldata->doc))) {
		objunref(xmldata);
		return NULL;
	}
	return xmldata;
}

/** @brief Load a XML file into XML document and return reference.
  * @param docfile Pathname to XML file.
  * @param validate Set to non zero value to fail if validation fails.
  * @returns XML Document or NULL on failure*/  
extern struct xml_doc *xml_loaddoc(const char *docfile, int validate) {
	struct xml_doc *xmldata;

	xml_init();

	if (!(xmldata = objalloc(sizeof(*xmldata), free_xmldata))) {
		return NULL;
	}

	if (!(xmldata->doc = xmlParseFile(docfile))) {
		objunref(xmldata);
		return NULL;
	}

	return xml_setup_parse(xmldata, validate);
}

/** @brief Load a buffer into XML document returning refereence.
  * @param buffer Buffer containing the XML.
  * @param len Size of the buffer.
  * @param validate Set to non zero value to fail if validation fails.
  * @returns XML Document or NULL on failure*/
extern struct xml_doc *xml_loadbuf(const uint8_t *buffer, uint32_t len, int validate) {
	struct xml_doc *xmldata;
	int flags;

	xml_init();

	if (!(xmldata = objalloc(sizeof(*xmldata), free_xmldata))) {
		return NULL;
	}

	if (validate) {
		flags = XML_PARSE_DTDLOAD | XML_PARSE_DTDVALID;
	} else {
		flags = XML_PARSE_DTDVALID;
	}

	if (!(xmldata->doc = xmlReadMemory((const char *)buffer, len, NULL, NULL, flags))) {
		objunref(xmldata);
		return NULL;
	}
	return xml_setup_parse(xmldata, 0);
}

static struct xml_node *xml_nodetohash(struct xml_doc *xmldoc, xmlNodePtr node, const char *attrkey) {
	struct xml_node *ninfo;
	struct xml_attr *ainfo;
	xmlChar *xmlstr;
	xmlAttr *attrs;

	if (!(ninfo = objalloc(sizeof(*ninfo), free_xmlnode))) {
		return NULL;
	}
	ninfo->attrs = NULL;

	if (!(ninfo->attrs = create_bucketlist(0, attr_hash))) {
		objunref(ninfo);
		return NULL;
	}

	ALLOC_CONST(ninfo->name, (const char *)node->name);
	xmlstr = xmlNodeListGetString(xmldoc->doc, node->xmlChildrenNode, 1);
	ALLOC_CONST(ninfo->value, (const char *)xmlstr);
	xmlFree(xmlstr);
	ninfo->nodeptr = node;

	attrs = node->properties;
	while(attrs && attrs->name && attrs->children) {
		if (!(ainfo = objalloc(sizeof(*ainfo), NULL))) {
			objunref(ninfo);
			return NULL;
		}
		ALLOC_CONST(ainfo->name, (const char *)attrs->name);
		xmlstr = xmlNodeListGetString(xmldoc->doc, attrs->children, 1);
		ALLOC_CONST(ainfo->value, (const char *)xmlstr);
		if (attrkey && !strcmp((const char *)attrs->name, (const char *)attrkey)) {
			ALLOC_CONST(ninfo->key, (const char *)xmlstr);
		}
		xmlFree(xmlstr);
		addtobucket(ninfo->attrs, ainfo);
		objunref(ainfo);
		attrs = attrs->next;
	}
	if (!attrkey && ninfo->value) {
		ALLOC_CONST(ninfo->key, ninfo->value);
	}
	return ninfo;
}

static struct xml_node *xml_gethash(struct xml_search *xpsearch, int i, const char *attrkey) {
	xmlNodePtr node;
	xmlNodeSetPtr nodeset;
	struct xml_node *xn;

	if (!objref(xpsearch)) {
		return NULL;
	}

	objlock(xpsearch->xmldoc);
	objlock(xpsearch);
	if (!(nodeset = xpsearch->xpathObj->nodesetval)) {
		objunlock(xpsearch);
		objunlock(xpsearch->xmldoc);
		objunref(xpsearch);
		return NULL;
	}

	if (!(node = nodeset->nodeTab[i])) {
		objunlock(xpsearch);
		objunlock(xpsearch->xmldoc);
		objunref(xpsearch);
		return NULL;
	}
	xn = xml_nodetohash(xpsearch->xmldoc, node, attrkey);
	objunlock(xpsearch);
	objunlock(xpsearch->xmldoc);
	objunref(xpsearch);

	return xn;
}

static void free_iter(void *data) {
	struct xml_node_iter *xi = data;

	objunref(xi->xsearch);
}

/** @brief Return reference to the root node.
  * @param xmldoc XML Document to find root in.*/
extern struct xml_node *xml_getrootnode(struct xml_doc *xmldoc) {
	struct xml_node *rn;

	objlock(xmldoc);
	rn = xml_nodetohash(xmldoc, xmldoc->root, NULL);
	objunlock(xmldoc);
	return rn;
}

/** @brief Return reference to the first node optionally creating a iterator.
  *
  * Setting the optional iterator and using it on future calls to xml_getnextnode
  * its possible to iterate through the search path.
  * @todo Thread safety when XML doc changes.
  * @note using xml_getnodes() returns a bucket list of nodes this is prefered.
  * @warning This is not thread safe.
  * @param xpsearch XML xpath search to find first node.
  * @param iter Optional iterator created and returned (must be unreferenced)
  * @returns Reference to first node in the path.*/
extern struct xml_node *xml_getfirstnode(struct xml_search *xpsearch, void **iter) {
	struct xml_node_iter *newiter;
	struct xml_node *xn;

	if (!objref(xpsearch)) {
		return NULL;
	}

	if (iter) {
		newiter = objalloc(sizeof(*newiter), free_iter);
		objlock(xpsearch);
		newiter->cnt = xml_nodecount(xpsearch);
		objunlock(xpsearch);
		newiter->curpos = 0;
		newiter->xsearch = xpsearch;
		objref(newiter->xsearch);
		*iter = newiter;
	}

	xn = xml_gethash(xpsearch, 0, NULL);
	objunref(xpsearch);
	return xn;
}

/** @brief Return the next node.
  * @param iter Iterator set in call to from xml_getfirstnode.
  * @returns Reference to next node.*/
extern struct xml_node *xml_getnextnode(void *iter) {
	struct xml_node_iter *xi = iter;
	struct xml_node *xn;

	if (!objref(xi->xsearch)) {
		return NULL;
	}

	objlock(xi);
	xi->curpos ++;
	if (xi->curpos >= xi->cnt) {
		objunlock(xi);
		objunref(xi->xsearch);
		return NULL;
	}
	xn = xml_gethash(xi->xsearch, xi->curpos, NULL);
	objunlock(xi);
	objunref(xi->xsearch);

	return xn;
}

/** @brief Return reference to bucket list containing nodes.
  * @note use of this is prefered to xml_getfirstnode() / xml_getnextnode() if
  * search order is not a issue.
  * @param xpsearch Reference to xpath search result returned by xml_xpath.
  * @returns Reference to bucket list containing nodes.*/
extern struct bucket_list *xml_getnodes(struct xml_search *xpsearch) {
	return (xpsearch && objref(xpsearch->nodes)) ? xpsearch->nodes : NULL;
}

static struct bucket_list *xml_setnodes(struct xml_search *xpsearch, const char *attrkey) {
	struct xml_node *ninfo;
	struct bucket_list *nodes;
	int cnt, i;

	if (!(nodes = create_bucketlist(2, node_hash))) {
		return NULL;
	}

	cnt = xml_nodecount(xpsearch);
	for(i=0; i < cnt; i++) {
		ninfo = xml_gethash(xpsearch, i, attrkey);
		if (!addtobucket(nodes, ninfo)) {
			objunref(ninfo);
			objunref(nodes);
			nodes = NULL;
			break;
		}
		objunref(ninfo);
	}
	return nodes;
}

/** @brief Return a reference to a xpath search result.
  * @param xmldata XML Document to search.
  * @param xpath Xpath search to apply.
  * @param attrkey Attribute to index by.
  * @returns Reference to XML search result.*/ 
extern struct xml_search *xml_xpath(struct xml_doc *xmldata, const char *xpath, const char *attrkey) {
	struct xml_search *xpsearch;

	if (!objref(xmldata) || !(xpsearch = objalloc(sizeof(*xpsearch), free_xmlsearch))) {
		return NULL;
	}

	objlock(xmldata);
	xpsearch->xmldoc = xmldata;
	if (!(xpsearch->xpathObj = xmlXPathEvalExpression((const xmlChar *)xpath, xmldata->xpathCtx))) {
		objunlock(xmldata);
		objunref(xpsearch);
		return NULL;
	}

	if (xmlXPathNodeSetIsEmpty(xpsearch->xpathObj->nodesetval)) {
		objunlock(xmldata);
		objunref(xpsearch);
		return NULL;
	}
	objunlock(xmldata);

	if (!(xpsearch->nodes = xml_setnodes(xpsearch, attrkey))) {
		objunref(xpsearch);
		return NULL;
	}
	return xpsearch;
}

/** @brief Return the number of nodes in the search path
  * @param xsearch Reference to XML xpath search (xml_xpath())
  * @returns Number of of nodes.*/
extern int xml_nodecount(struct xml_search *xsearch) {
	xmlNodeSetPtr nodeset;

	if (xsearch && xsearch->xpathObj && ((nodeset = xsearch->xpathObj->nodesetval))) {
		return nodeset->nodeNr;
	} else {
		return 0;
	}
}

/** @brief Return a node in the search matching key.
  *
  * The key is matched against the index attribute supplied or the value of the node.
  * @param xsearch Reference to xpath search.
  * @param key Value to use to find node matched aginst the index attribute/value.
  * @returns Reference to XML node.*/
extern struct xml_node *xml_getnode(struct xml_search *xsearch, const char *key) {
	if (!xsearch) {
		return NULL;
	}
	return bucket_list_find_key(xsearch->nodes, key);
}

/** @brief Return value of attribute.
  * @param xnode XML node reference.
  * @param attr Attribute to search for.
  * @returns Value of the attribute valid while reference to node is held.*/
extern const char *xml_getattr(struct xml_node *xnode, const char *attr) {
	struct xml_attr *ainfo;

	if (!xnode) {
		return NULL;
	}

	if ((ainfo = bucket_list_find_key(xnode->attrs, attr))) {
		objunref(ainfo);
		return ainfo->value;
	} else {
		return NULL;
	}
}

/** @brief Return the name of the root node.
  * @note do not free or unref this.
  * @param xmldoc XML Document.*/
extern const char *xml_getrootname(struct xml_doc *xmldoc) {
	if (xmldoc) {
		return (const char *)xmldoc->root->name;
	}
	return NULL;
}

/** @brief Modify a XML node.
  * @param xmldoc XML Document node belongs to
  * @param xnode XML Node to modify.
  * @param value Value to set.*/
extern void xml_modify(struct xml_doc *xmldoc, struct xml_node *xnode, const char *value) {
	xmlChar *encval;
	xmlNodePtr node;

	objlock(xmldoc);
	node = xnode->nodeptr;
	encval = xmlEncodeSpecialChars(xmldoc->doc, (const xmlChar *)value);
	xmlNodeSetContent(node, encval);
	xmlFree(encval);
	encval = xmlNodeListGetString(xmldoc->doc, node->xmlChildrenNode, 1);
	objunlock(xmldoc);

	if (xnode->value) {
		free((void*)xnode->value);
	}
	ALLOC_CONST(xnode->value, (const char *)encval);
	xmlFree(encval);
}

/** @brief Modify a XML node attribute.
  * @param xmldoc XML Document node belongs to
  * @param xnode XML Node to modify.
  * @param name Attribute to modify.
  * @param value Value to set.*/
extern void xml_setattr(struct xml_doc *xmldoc, struct xml_node *xnode, const char *name, const char *value) {
	xmlChar *encval;

	objlock(xmldoc);
	encval = xmlEncodeSpecialChars(xmldoc->doc, (const xmlChar *)value);
	xmlSetProp(xnode->nodeptr, (const xmlChar *)name, (const xmlChar *)encval);
	objunlock(xmldoc);
	xmlFree(encval);
}

/** @brief Create a path in XML document.
  * @note xpath is not a full xpath just a path [no filters].
  * @param xmldoc Reference to XML document.
  * @param xpath Path to create.*/
extern void xml_createpath(struct xml_doc *xmldoc, const char *xpath) {
	struct xml_node *nn;
	xmlXPathObjectPtr xpathObj;
	char *lpath, *tok, *save, *cpath, *dup;
	const char *root = (char *)xmldoc->root->name;
	int len;


	if (!objref(xmldoc)) {
		return;
	}

	if (!(dup = strdup(xpath))) {
		objunref(xmldoc);
		return;
	}

	len = strlen(xpath)+1;
	if (!(cpath = malloc(len))) {
		free(dup);
		objunref(xmldoc);
		return;
	}
	if (!(lpath = malloc(len))) {
		free(dup);
		free(cpath);
		objunref(xmldoc);
		return;
	}

	cpath[0] = '\0';
	lpath[0] = '\0';

#ifndef __WIN32__
		for (tok = strtok_r(dup, "/", &save); tok ; tok = strtok_r(NULL, "/", &save)) {
#else
		for (tok = strtok_s(dup, "/", &save); tok ; tok = strtok_s(NULL, "/", &save)) {
#endif
		strcat(cpath,"/");
		strcat(cpath, tok);
		if (!strcmp(tok, root)) {
			strcat(lpath,"/");
			strcat(lpath, tok);
			continue;
		}

		objlock(xmldoc);
		if (!(xpathObj = xmlXPathEvalExpression((const xmlChar *)cpath, xmldoc->xpathCtx))) {
			objunlock(xmldoc);
			free(lpath);
			free(cpath);
			free(dup);
			objunref(xmldoc);
			return;
		}
		objunlock(xmldoc);

		if (xmlXPathNodeSetIsEmpty(xpathObj->nodesetval)) {
			nn = xml_addnode(xmldoc, lpath, tok, NULL, NULL, NULL);
			objunref(nn);
		}

		xmlXPathFreeObject(xpathObj);
		strcat(lpath,"/");
		strcat(lpath, tok);
	}

	free(dup);
	free(lpath);
	free(cpath);
	objunref(xmldoc);
}


static xmlNodePtr xml_getparent(struct xml_doc *xmldoc, const char *xpath) {
	xmlXPathObjectPtr xpathObj;
	xmlNodePtr parent = NULL;
	xmlNodeSetPtr nodes;
	int i, cnt;

	if (!(xpathObj = xmlXPathEvalExpression((const xmlChar *)xpath, xmldoc->xpathCtx))) {
		return NULL;
	}

	if (xmlXPathNodeSetIsEmpty(xpathObj->nodesetval)) {
		xmlXPathFreeObject(xpathObj);
		return NULL;
	}

	if (!(nodes = xpathObj->nodesetval)) {
		xmlXPathFreeObject(xpathObj);
		return NULL;
	}

	cnt = nodes->nodeNr;
	for(i=cnt - 1; i >= 0; i--) {
		if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
			parent=nodes->nodeTab[i];
			nodes->nodeTab[i] = NULL;
			break;
		}
	}

	if (!parent) {
		xmlXPathFreeObject(xpathObj);
		return NULL;
	}

	xmlXPathFreeObject(xpathObj);
	return parent;
}


/** @brief Append a node to a path.
  * @note The child will most likely be a node unlinked and moved.
  * @param xmldoc Reference to XML document.
  * @param xpath Path to add the node too.
  * @param child XML node to append to path.*/
extern void xml_appendnode(struct xml_doc *xmldoc, const char *xpath, struct  xml_node *child) {
	xmlNodePtr parent;

	if (!objref(xmldoc)) {
		return;
	}

	objlock(xmldoc);
	if (!(parent = xml_getparent(xmldoc, xpath))) {
		objunlock(xmldoc);
		objunref(xmldoc);
	}

	xmlAddChild(parent,child->nodeptr);
	objunlock(xmldoc);
	objunref(xmldoc);
}

/** @brief Append a node to a path.
  * @param xmldoc Reference to XML document.
  * @param xpath Path to add the node too.
  * @param name Node name.
  * @param value Node value.
  * @param attrkey Attribute to create on node.
  * @param keyval Attribute value of attrkey.
  * @returns reference to new node.*/
extern struct xml_node *xml_addnode(struct xml_doc *xmldoc, const char *xpath, const char *name, const char *value,
									const char *attrkey, const char *keyval) {
	struct xml_node *newnode;
	xmlNodePtr parent;
	xmlNodePtr child;
	xmlChar *encval;

	if (!objref(xmldoc)) {
		return NULL;
	}

	objlock(xmldoc);
	if (!(parent = xml_getparent(xmldoc, xpath))) {
		objunlock(xmldoc);
		objunref(xmldoc);
		return NULL;
	}

	encval = xmlEncodeSpecialChars(xmldoc->doc, (const xmlChar *)value);
	child = xmlNewDocNode(xmldoc->doc, NULL, (const xmlChar *)name, encval);
	xmlFree(encval);
	xmlAddChild(parent,child);

	if (attrkey && keyval) {
		encval = xmlEncodeSpecialChars(xmldoc->doc, (const xmlChar *)keyval);
		xmlSetProp(child, (const xmlChar *)attrkey, (const xmlChar *)encval);
		xmlFree(encval);
	}
	objunlock(xmldoc);

	if (!(newnode = xml_nodetohash(xmldoc, child, attrkey))) {
		objunref(xmldoc);
		return NULL;
	}

	objunref(xmldoc);

	return newnode;
}

/** @brief Unlink a node from the document.
  * @param xnode Reference of node to unlink.*/
extern void xml_unlink(struct xml_node *xnode) {
	objlock(xnode);
	xmlUnlinkNode(xnode->nodeptr);
	objunlock(xnode);
}

/** @brief Delete a node from document it is not unrefd and should be.
  * @param xnode Reference to node to delete this must be unreferenced after calling this function.*/
extern void xml_delete(struct xml_node *xnode) {
	objlock(xnode);
	xmlUnlinkNode(xnode->nodeptr);
	xmlFreeNode(xnode->nodeptr);
	xnode->nodeptr = NULL;
	objunlock(xnode);
}

/** @brief Return the buffer of a xml_buffer structure
  * @note only valid while reference is held to the xml_buffer struct.
  * @param buffer Reference to a xml_buffer struct.*/
extern char *xml_getbuffer(void *buffer) {
	struct xml_buffer *xb = buffer;

	if (!xb) {
		return NULL;
	}
	return (char *)xb->buffer;
}

/** @brief Return a dump of a XML document.
  *
  * The result can be acessed using xml_getbuffer()
  * @param xmldoc Reference to a XML document.
  * @returns Reference to a xml_buffer structure.*/
extern void *xml_doctobuffer(struct xml_doc *xmldoc) {
	struct xml_buffer *xmlbuf;

	if (!(xmlbuf = objalloc(sizeof(*xmlbuf),xml_free_buffer))) {
		return NULL;
	}

	objlock(xmldoc);
	xmlDocDumpFormatMemory(xmldoc->doc, &xmlbuf->buffer, &xmlbuf->size, 1);
	objunlock(xmldoc);
	return xmlbuf;
}

/** @brief Initialise/Reference the XML library
  *
  * Ideally this should be done on application startup but will be started and stoped as needed.*/
extern void xml_init() {
	if (!xml_has_init_parser) {
		xml_has_init_parser = objalloc(0, free_parser);
		xmlInitParser();
		LIBXML_TEST_VERSION
		xmlKeepBlanksDefault(0);
		xmlLoadExtDtdDefaultValue = 1;
		xmlSubstituteEntitiesDefault(1);
	} else {
		objref(xml_has_init_parser);
	}
}

/** @brief Unreference the XML library
  *
  * Ideally this should be done after a call to xml_init at shutdown.*/
extern void xml_close() {
	if (xml_has_init_parser) {
		objunref(xml_has_init_parser);
	}
}

/** @brief Save XML document to a file.
  * @param xmldoc Reference to XML document to save.
  * @param file Filename to write the XML document too.
  * @param format Formating flag from libxml2.
  * @param compress Compression level 0[none]-9.*/
extern void xml_savefile(struct xml_doc *xmldoc, const char *file, int format, int compress) {
	objlock(xmldoc);
	xmlSetDocCompressMode(xmldoc->doc, compress);
	xmlSaveFormatFile(file, xmldoc->doc, format);
	xmlSetDocCompressMode(xmldoc->doc, 0);
	objunlock(xmldoc);
}

/*static void xml_modify2(struct xml_search *xpsearch, struct xml_node *xnode, const char *value) {
	xmlNodeSetPtr nodes;
	int size, i;

	if (!(nodes = xpsearch->xpathObj->nodesetval)) {
		return;
	}

	size = (nodes) ? nodes->nodeNr : 0;

*/	/*
	 * http://www.xmlsoft.org/examples/xpath2.c
	 * remove the reference to the modified nodes from the node set
	 * as they are processed, if they are not namespace nodes.
	*/
/*	for(i = size - 1; i >= 0; i--) {
		if (nodes->nodeTab[i] == xnode->nodeptr) {
			xmlNodeSetContent(nodes->nodeTab[i], (const xmlChar *)value);
			if (nodes->nodeTab[i]->type != XML_NAMESPACE_DECL) {
				nodes->nodeTab[i] = NULL;
			}
		}
	}
}*/

/** @}*/
