#include <string.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "include/priv_xml.h"
#include "include/dtsapp.h"

extern int xmlLoadExtwDtdDefaultValue;

struct xml_node_iter {
	struct xml_search *xsearch;
	int curpos;
	int cnt;
};

struct xml_buffer {
	xmlChar *buffer;
	int size;
};

struct xml_search {
	struct xml_doc *xmldoc;
	xmlXPathObjectPtr xpathObj;
	struct bucket_list *nodes;
};

static void *xml_has_init_parser = NULL;

static void free_buffer(void *data) {
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
		free((char*)ninfo->name);
	}
	if (ninfo->key) {
		free((char*)ninfo->key);
	}
	if (ninfo->value) {
		free((char*)ninfo->value);
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

int node_hash(const void *data, int key) {
	int ret;
	const struct xml_node *ni = data;
	const char* hashkey = (key) ? data : ni->key;

	if (hashkey) {
		ret = jenhash(hashkey, strlen(hashkey), 0);
	} else {
		ret = jenhash(ni, sizeof(ni), 0);
	}
	return(ret);
}

int attr_hash(const void *data, int key) {
	int ret;
	const struct xml_attr *ai = data;
	const char* hashkey = (key) ? data : ai->name;

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
/*		xmlValidateDocumentFinal(xmldata->ValidCtxt, xmldata->doc);*/
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

extern struct xml_doc *xml_loaddoc(const char* docfile, int validate) {
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

extern struct xml_doc *xml_loadbuf(const char* buffer, int len, int validate) {
	struct xml_doc *xmldata;

	xml_init();

	if (!(xmldata = objalloc(sizeof(*xmldata), free_xmldata))) {
		return NULL;
	}

	if (!(xmldata->doc = xmlParseMemory(buffer, len))) {
		objunref(xmldata);
		return NULL;
	}

	return xml_setup_parse(xmldata, validate);
}

struct xml_node *xml_nodetohash(struct xml_doc *xmldoc, xmlNodePtr node, const char *attrkey) {
	struct xml_node *ninfo;
	struct xml_attr *ainfo;
	xmlChar *xmlstr;
	xmlAttr* attrs;

	if (!(ninfo = objalloc(sizeof(*ninfo), free_xmlnode))) {
		return NULL;
	}
	ninfo->attrs = NULL;

	if (!(ninfo->attrs = create_bucketlist(0, attr_hash))) {
		objunref(ninfo);
		return NULL;
	}

	ALLOC_CONST(ninfo->name, (const char*)node->name);
	xmlstr = xmlNodeListGetString(xmldoc->doc, node->xmlChildrenNode, 1);
	ALLOC_CONST(ninfo->value, (const char*)xmlstr);
	xmlFree(xmlstr);
	ninfo->nodeptr = node;

	attrs = node->properties;
	while(attrs && attrs->name && attrs->children) {
		if (!(ainfo = objalloc(sizeof(*ainfo), NULL))) {
			objunref(ninfo);
			return NULL;
		}
		ALLOC_CONST(ainfo->name, (const char*)attrs->name);
		xmlstr = xmlNodeListGetString(xmldoc->doc, attrs->children, 1);
		ALLOC_CONST(ainfo->value, (const char*)xmlstr);
		if (attrkey && !strcmp((const char*)attrs->name, (const char*)attrkey)) {
			ALLOC_CONST(ninfo->key, (const char*)xmlstr);
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

struct xml_node *xml_gethash(struct xml_search *xpsearch, int i, const char* attrkey) {
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

extern struct xml_node *xml_getrootnode(struct xml_doc *xmldoc) {
	struct xml_node *rn;

	objlock(xmldoc);
	rn = xml_nodetohash(xmldoc, xmldoc->root, NULL);
	objunlock(xmldoc);
	return rn;
}

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

extern struct bucket_list *xml_getnodes(struct xml_search *xpsearch) {
	if (!xpsearch) {
		return NULL;
	}
	return xpsearch->nodes;
}

struct bucket_list *xml_setnodes(struct xml_search *xpsearch, const char* attrkey) {
	struct xml_node *ninfo;
	struct bucket_list *nodes;
	int cnt, i;

	if (!(nodes = create_bucketlist(2, node_hash))) {
		return NULL;
	}

	cnt = xml_nodecount(xpsearch);
	for(i=0; i < cnt;i++) {
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

extern struct xml_search *xml_xpath(struct xml_doc *xmldata, const char *xpath, const char *attrkey) {
	struct xml_search *xpsearch;

	if (!objref(xmldata) || !(xpsearch = objalloc(sizeof(*xpsearch), free_xmlsearch))) {
		return NULL;
	}

	objlock(xmldata);
	xpsearch->xmldoc = xmldata;
	if (!(xpsearch->xpathObj = xmlXPathEvalExpression((const xmlChar*)xpath, xmldata->xpathCtx))) {
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

extern int xml_nodecount(struct xml_search *xsearch) {
	xmlNodeSetPtr nodeset;

	if (xsearch && xsearch->xpathObj && ((nodeset = xsearch->xpathObj->nodesetval))) {
		return nodeset->nodeNr;
	} else {
		return 0;
	}
}

extern struct xml_node *xml_getnode(struct xml_search *xsearch, const char *key) {
	if (!xsearch) {
		return NULL;
	}
	return bucket_list_find_key(xsearch->nodes, key);
}

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

extern const char *xml_getrootname(struct xml_doc *xmldoc) {
	if (xmldoc) {
		return (const char*)xmldoc->root->name;
	}
	return NULL;
}

extern void xml_modify(struct xml_doc *xmldoc, struct xml_node *xnode, const char *value) {
	xmlChar *encval;

	objlock(xmldoc);
	encval = xmlEncodeSpecialChars(xmldoc->doc, (const xmlChar*)value);
	xmlNodeSetContent(xnode->nodeptr, encval);
	objunlock(xmldoc);
	xmlFree(encval);
}

extern void xml_setattr(struct xml_doc *xmldoc, struct xml_node *xnode, const char *name, const char *value) {
	xmlChar *encval;

	objlock(xmldoc);
	encval = xmlEncodeSpecialChars(xmldoc->doc, (const xmlChar*)value);
	xmlSetProp(xnode->nodeptr, (const xmlChar*)name, (const xmlChar*)encval);
	objunlock(xmldoc);
	xmlFree(encval);
}

extern void xml_createpath(struct xml_doc *xmldoc, const char *xpath) {
	struct xml_node *nn;
	xmlXPathObjectPtr xpathObj;
	char *lpath, *tok, *save, *cpath, *dup;
	const char *root = (char*)xmldoc->root->name;
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

	for (tok = strtok_r(dup, "/", &save); tok ;tok = strtok_r(NULL, "/", &save)) {
		strcat(cpath,"/");
		strcat(cpath, tok);
		if (!strcmp(tok, root)) {
			strcat(lpath,"/");
			strcat(lpath, tok);
			continue;
		}

		objlock(xmldoc);
		if (!(xpathObj = xmlXPathEvalExpression((const xmlChar*)cpath, xmldoc->xpathCtx))) {
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

extern struct xml_node *xml_addnode(struct xml_doc *xmldoc, const char *xpath, const char *name, const char *value,
					const char* attrkey, const char* keyval) {
	xmlXPathObjectPtr xpathObj;
	struct xml_node *newnode;
	xmlNodeSetPtr nodes;
	xmlNodePtr parent = NULL;
	xmlNodePtr child;
	xmlChar *encval;
	int i,cnt;

	if (!objref(xmldoc)) {
		return NULL;
	}

	objlock(xmldoc);
	if (!(xpathObj = xmlXPathEvalExpression((const xmlChar*)xpath, xmldoc->xpathCtx))) {
		objunlock(xmldoc);
		objunref(xmldoc);
		return NULL;
	}

	if (xmlXPathNodeSetIsEmpty(xpathObj->nodesetval)) {
		objunlock(xmldoc);
		xmlXPathFreeObject(xpathObj);
		objunref(xmldoc);
		return NULL;
	}

	if (!(nodes = xpathObj->nodesetval)) {
		objunlock(xmldoc);
		xmlXPathFreeObject(xpathObj);
		objunref(xmldoc);
		return NULL;
	}

	cnt = nodes->nodeNr;
	for(i=cnt - 1; i >= 0;i--) {
		if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
			parent=nodes->nodeTab[i];
			nodes->nodeTab[i] = NULL;
			break;
		}
	}

	if (!parent) {
		objunlock(xmldoc);
		xmlXPathFreeObject(xpathObj);
		objunref(xmldoc);
		return NULL;
	}

	encval = xmlEncodeSpecialChars(xmldoc->doc, (const xmlChar*)value);
	child = xmlNewDocNode(xmldoc->doc, NULL, (const xmlChar*)name, encval);
	xmlAddChild(parent,child);
	objunlock(xmldoc);
	xmlFree(encval);
	xmlXPathFreeObject(xpathObj);

	if (!(newnode = xml_nodetohash(xmldoc, child, attrkey))) {
		objunref(xmldoc);
		return NULL;
	}

	if (attrkey && keyval) {
		xml_setattr(xmldoc, newnode, attrkey, keyval);
	}

	objunref(xmldoc);

	return newnode;
}

extern void xml_delete(struct xml_node *xnode) {
	objlock(xnode);
	xmlUnlinkNode(xnode->nodeptr);
	xmlFreeNode(xnode->nodeptr);
	xnode->nodeptr = NULL;
	objunlock(xnode);
}

extern char *xml_getbuffer(void *buffer) {
	struct xml_buffer *xb = buffer;

	if (!xb) {
		return NULL;
	}
	return (char*)xb->buffer;
}

extern void *xml_doctobuffer(struct xml_doc *xmldoc) {
	struct xml_buffer *xmlbuf;

	if (!(xmlbuf = objalloc(sizeof(*xmlbuf),free_buffer))) {
		return NULL;
	}

	objlock(xmldoc);
	xmlDocDumpFormatMemory(xmldoc->doc, &xmlbuf->buffer, &xmlbuf->size, 1);
	objunlock(xmldoc);
	return xmlbuf;
}

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

extern void xml_close() {
	if (xml_has_init_parser) {
		objunref(xml_has_init_parser);
	}
}

extern void xml_savefile(struct xml_doc *xmldoc, const char *file, int format, int compress) {
	objlock(xmldoc);
	xmlSetDocCompressMode(xmldoc->doc, compress);
	xmlSaveFormatFile(file, xmldoc->doc, format);
	xmlSetDocCompressMode(xmldoc->doc, 0);
	objunlock(xmldoc);
}

extern void xml_modify2(struct xml_search *xpsearch, struct xml_node *xnode, const char *value) {
	xmlNodeSetPtr nodes;
	int size, i;

	if (!(nodes = xpsearch->xpathObj->nodesetval)) {
		return;
	}

	size = (nodes) ? nodes->nodeNr : 0;

	/*
	 * http://www.xmlsoft.org/examples/xpath2.c
	 * remove the reference to the modified nodes from the node set
	 * as they are processed, if they are not namespace nodes.
	*/
	for(i = size - 1; i >= 0; i--) {
		if (nodes->nodeTab[i] == xnode->nodeptr) {
			xmlNodeSetContent(nodes->nodeTab[i], (const xmlChar*)value);
			if (nodes->nodeTab[i]->type != XML_NAMESPACE_DECL) {
				nodes->nodeTab[i] = NULL;
			}
		}
	}
}
