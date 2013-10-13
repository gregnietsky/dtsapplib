/*
Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za>
        http://www.distrotech.co.za

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Acknowledgments [MD5 HMAC http://www.ietf.org/rfc/rfc2104.txt]
 *	Pau-Chen Cheng, Jeff Kraemer, and Michael Oehler, have provided
 *	useful comments on early drafts, and ran the first interoperability
 *	tests of this specification. Jeff and Pau-Chen kindly provided the
 *	sample code and test vectors that appear in the appendix.  Burt
 *	Kaliski, Bart Preneel, Matt Robshaw, Adi Shamir, and Paul van
 *	Oorschot have provided useful comments and suggestions during the
 *	investigation of the HMAC construction.
 */

/*
 * User password crypt function from the freeradius project (addattrpasswd)
 * Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 The FreeRADIUS Server Project
 */

/** @defgroup LIB Distrotech Application Library
  * @brief A Collection of helper functions and wrapped up interfaces to other libraries
  * @file
  * @brief DTS Application library API Include file.
  * 
  * @ingroup LIB
  * The library foremostly implements reference counted objects and hashed bucket lists
  * @ref LIB-OBJ these are then used to implement simpler API's to common tasks.
  * @par Key components
  * @n INI style config file parser.
  * @n CURL wraper with support for GET/POST, authentification and progress indication.
  * @n File utilities as a wrapper arround fstat.
  * @n IP 4/6 Utilities for calculating / checking subnets and checksuming packets.
  * @n Interface API for Linux networking including libnetlink from iproute2
  * @n XML/XSLT Simplified API for reading, managing and applying transforms.
  * @n Some Application shortcuts and wrapper for main quick and dirty daemon app.
  * @n Wrappers for Linux netfilter connection tracking and packet queueing
  * @n Open LDAP API.
  * @n Basic implementation of RADIUS.
  * @n Implementation of RFC 6296.
  * @n Thread API using pthreads.
  * @n Simple implementation of UNIX Domain socket.
  * @n Various Utilities including hashing and checksum.
  * @n Z Lib Compression/Uncompression Functions.*/ 

#ifndef _INCLUDE_DTSAPP_H
#define _INCLUDE_DTSAPP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <signal.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2ipdef.h>
#else
#include <arpa/inet.h>
#endif

/*socket structure*/
union sockstruct {
	struct sockaddr sa;
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	struct sockaddr_storage ss;
};

/** @brief Forward decleration of structure.*/
typedef struct ssldata ssldata;

enum sock_flags {
	SOCK_FLAG_BIND		= 1 << 0,
	SOCK_FLAG_CLOSE		= 1 << 1
};

struct fwsocket {
	int sock;
	int proto;
	int type;
	enum sock_flags flags;
	union sockstruct addr;
	struct ssldata *ssl;
	struct fwsocket *parent;
	struct bucket_list *children;
};

struct config_entry {
	const char *item;
	const char *value;
};

/** @ingroup LIB-Z
  * @brief Zlib buffer used for compression and decompression*/
struct zobj {
	/** @brief Buffer with compressed/uncompressed data*/
	uint8_t *buff;
	/** @brief Original size of data*/
	uint16_t olen;
	/** @brief Compressed size of data*/
	uint16_t zlen;
};

/** @brief Forward decleration of structure.*/
typedef struct natmap natmap;
/** @brief Forward decleration of structure.*/
typedef struct radius_packet radius_packet;
/** @brief Forward decleration of structure.*/
typedef struct nfq_queue nfq_queue;
/** @brief Forward decleration of structure.*/
typedef struct nfq_data nfq_data;
/** @brief Forward decleration of structure.*/
typedef struct nfct_struct nfct_struct;
/** @brief Forward decleration of structure.*/
typedef struct nfqnl_msg_packet_hdr nfqnl_msg_packet_hdr;

/*callback function type def's*/
typedef void	(*radius_cb)(struct radius_packet *, void *);
/** @brief Framework callback function
  *
  * @ingroup LIB
  * @param argc Argument count.
  * @param argv Argument array.
  * @returns Application exit code.*/
typedef	int	(*frameworkfunc)(int, char **);
/** @brief Callback to user supplied signal handler.
  *
  * @ingroup LIB
  * @param sig Signal been handled.
  * @param si Sa sigaction.
  * @param unsed Unused cast to void from ucontext_t*/
#ifndef __WIN32__
typedef void	(*syssighandler)(int, siginfo_t *, void *);
#else
typedef void	(*syssighandler)(int, void*, void*);
#endif
/** @brief Function called after thread termination.
  *
  * @ingroup LIB-Thread
  * @see framework_mkthread()
  * @param data Reference of thread data.*/
typedef void    (*threadcleanup)(void *);
/** @brief Thread function
  *
  * @ingroup LIB-Thread
  * @see framework_mkthread()
  * @param data Poinnter to reference of thread data.*/
typedef void    *(*threadfunc)(void **);
/** @brief Thread signal handler function
  *
  * @ingroup LIB-Thread
  * @see framework_mkthread()
  * @param data Reference of thread data.*/
typedef int     (*threadsighandler)(int, void *);
typedef int	(*blisthash)(const void *, int);
typedef void	(*objdestroy)(void *);
typedef void	(*socketrecv)(struct fwsocket *, void *);
typedef void	(*blist_cb)(void *, void *);
typedef void	(*config_filecb)(struct bucket_list *, const char *, const char *);
typedef void	(*config_catcb)(struct bucket_list *, const char *);
typedef void	(*config_entrycb)(const char *, const char *);
typedef uint32_t (*nfqueue_cb)(struct nfq_data *, struct nfqnl_msg_packet_hdr *, char *, uint32_t, void *, uint32_t *, void **);

/** @brief Application control flags
  * @ingroup LIB*/
enum framework_flags {
	/** @brief Allow application daemonization.*/
	FRAMEWORK_FLAG_DAEMON	= 1 << 0,
	/** @brief Dont print GNU copyright.*/
	FRAMEWORK_FLAG_NOGNU	= 1 << 1,
	/** @brief Dont start thread manager.*/
	FRAMEWORK_FLAG_NOTHREAD	= 1 << 2
};

/** @brief Application framework data
  * @see framework_mkcore()
  * @see framework_init()
  * @see FRAMEWORK_MAIN()*/
struct framework_core {
	/** @brief Developer/Copyright holder*/
	const char *developer;
	/** @brief Email address of copyright holder*/
	const char *email;
	/** @brief URL displayed (use full URL ie with http://)*/
	const char *www;
	/** @brief File to write PID too and lock*/
	const char *runfile;
	/** @brief Detailed application name*/
	const char *progname;
	/** @brief Copyright year*/
	int  year;
	/** @brief if there is a file locked this is the FD that will be unlocked and unlinked*/
	int  flock;
	/** @brief sigaction structure allocated on execution*/
	struct sigaction *sa;
	/** @brief Signal handler to pass signals too
	  * @note The application framework installs a signal handler but will pass calls to this as a callback*/
	syssighandler	sig_handler;
	/** @brief Application Options
	  * @see application_flags*/
	int flags;
};

void framework_mkcore(char *progname, char *name, char *email, char *web, int year, char *runfile, int flags, syssighandler sigfunc);
extern int framework_init(int argc, char *argv[], frameworkfunc callback);
void printgnu();
void daemonize();
int lockpidfile(const char *runfile);
extern struct thread_pvt *framework_mkthread(threadfunc, threadcleanup, threadsighandler, void *data);
/* UNIX Socket*/
extern void framework_unixsocket(char *sock, int protocol, int mask, threadfunc connectfunc, threadcleanup cleanup);
/* Test if the thread is running when passed data from thread */
extern int framework_threadok(void *data);
extern int startthreads(void);
extern void stopthreads(void);

/*
 * ref counted objects
 */
extern int objlock(void *data);
extern int objtrylock(void *data);
extern int objunlock(void *data);
extern int objcnt(void *data);
extern int objsize(void *data);
extern int objunref(void *data);
extern int objref(void *data);
extern void *objalloc(int size, objdestroy);
void *objchar(const char *orig);

/*
 * hashed bucket lists
 */
extern void *create_bucketlist(int bitmask, blisthash hash_function);
extern int addtobucket(struct bucket_list *blist, void *data);
extern void remove_bucket_item(struct bucket_list *blist, void *data);
extern int bucket_list_cnt(struct bucket_list *blist);
extern void *bucket_list_find_key(struct bucket_list *list, const void *key);
extern void bucketlist_callback(struct bucket_list *blist, blist_cb callback, void *data2);

/*
 * iteration through buckets
 */
extern struct bucket_loop *init_bucket_loop(struct bucket_list *blist);
extern void stop_bucket_loop(struct bucket_loop *bloop);
extern void *next_bucket_loop(struct bucket_loop *bloop);
extern void remove_bucket_loop(struct bucket_loop *bloop);

/*include jenkins hash burttlebob*/
extern uint32_t hashlittle(const void *key, size_t length, uint32_t initval);


/*
 * Utilities RNG/MD5 used from the openssl library
 */
extern void seedrand(void);
extern int genrand(void *buf, int len);
extern void sha512sum(unsigned char *buff, const void *data, unsigned long len);
extern void sha256sum(unsigned char *buff, const void *data, unsigned long len);
extern void sha1sum(unsigned char *buff, const void *data, unsigned long len);
extern void md5sum(unsigned char *buff, const void *data, unsigned long len);
extern void sha512sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2);
extern void sha256sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2);
extern void sha1sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2);
extern void md5sum2(unsigned char *buff, const void *data, unsigned long len, const void *data2, unsigned long len2);
extern int sha512cmp(unsigned char *digest1, unsigned char *digest2);
extern int sha256cmp(unsigned char *digest1, unsigned char *digest2);
extern int sha1cmp(unsigned char *digest1, unsigned char *digest2);
extern int md5cmp(unsigned char *digest1, unsigned char *digest2);
extern void sha512hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen);
extern void sha256hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen);
extern void sha1hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen);
extern void md5hmac(unsigned char *buff, const void *data, unsigned long len, const void *key, unsigned long klen);
extern int strlenzero(const char *str);
extern char *ltrim(char *str);
extern char *rtrim(const char *str);
extern char *trim(const char *str);
extern uint64_t tvtontp64(struct timeval *tv);
extern uint16_t checksum(const void *data, int len);
extern uint16_t checksum_add(const uint16_t checksum, const void *data, int len);
extern uint16_t verifysum(const void *data, int len, const uint16_t check);
extern struct zobj *zcompress(uint8_t *buff, uint16_t len, uint8_t level);
extern void zuncompress(struct zobj *buff, uint8_t *obuff);
extern uint8_t *gzinflatebuf(uint8_t *buf_in, int buf_size, uint32_t *len);
extern int is_gzip(uint8_t *buf, int buf_size);
#ifdef __WIN32__
extern void touch(const char *filename);
#else
extern void touch(const char *filename, uid_t user, gid_t group);
#endif
extern char *b64enc(const char *message, int nonl);
extern char *b64enc_buf(const char *message, uint32_t len, int nonl);

/*IP Utilities*/
extern struct fwsocket *make_socket(int family, int type, int proto, void *ssl);
extern struct fwsocket *sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *udpconnect(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *tcpconnect(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int backlog);
extern struct fwsocket *udpbind(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *tcpbind(const char *ipaddr, const char *port, void *ssl, int backlog);
extern void close_socket(struct fwsocket *sock);

extern void socketclient(struct fwsocket *sock, void *data, socketrecv read, threadcleanup cleanup);
extern void socketserver(struct fwsocket *sock, socketrecv connectfunc, socketrecv acceptfunc, threadcleanup cleanup, void *data);

/*IP Utilities*/
extern int checkipv6mask(const char *ipaddr, const char *network, uint8_t bits);
extern void ipv4tcpchecksum(uint8_t *pkt);
extern void ipv4udpchecksum(uint8_t *pkt);
extern void icmpchecksum(uint8_t *pkt);
extern void ipv4checksum(uint8_t *pkt);
extern int packetchecksumv4(uint8_t *pkt);
extern int packetchecksumv6(uint8_t *pkt);
extern int packetchecksum(uint8_t *pkt);
extern void rfc6296_map(struct natmap *map, struct in6_addr *ipaddr, int out);
extern int rfc6296_map_add(char *intaddr, char *extaddr);
const char *cidrtosn(int bitlen, const char *buf, int size);
const char *getnetaddr(const char *ipaddr, int cidr, const char *buf, int size);
const char *getbcaddr(const char *ipaddr, int cidr, const char *buf, int size);
const char *getfirstaddr(const char *ipaddr, int cidr, const char *buf, int size);
const char *getlastaddr(const char *ipaddr, int cidr, const char *buf, int size);
uint32_t cidrcnt(int bitlen);
int reservedip(const char *ipaddr);
char* ipv6to4prefix(const char *ipaddr);
int check_ipv4(const char* ip, int cidr, const char *test);

/*netfilter queue*/
extern struct nfq_queue *nfqueue_attach(uint16_t pf, uint16_t num, uint8_t mode, uint32_t range, nfqueue_cb cb, void *data);
extern uint16_t snprintf_pkt(struct nfq_data *tb, struct nfqnl_msg_packet_hdr *ph, uint8_t *pkt, char *buff, uint16_t len);
extern struct nf_conntrack *nf_ctrack_buildct(uint8_t *pkt);
extern uint8_t nf_ctrack_delete(uint8_t *pkt);
extern uint8_t nf_ctrack_nat(uint8_t *pkt, uint32_t addr, uint16_t port, uint8_t dnat);
extern void nf_ctrack_dump(void);
extern struct nfct_struct *nf_ctrack_trace(void);
extern void nf_ctrack_endtrace(struct nfct_struct *nfct);
extern uint8_t nf_ctrack_init(void);
extern void nf_ctrack_close(void);

/*interface functions*/
extern int delete_kernvlan(char *ifname, int vid);
extern int create_kernvlan(char *ifname, unsigned short vid);
extern int delete_kernmac(char *macdev);
extern int create_kernmac(char *ifname, char *macdev, unsigned char *mac);
extern int interface_bind(char *iface, int protocol, int flags);
extern void randhwaddr(unsigned char *addr);
extern int create_tun(const char *ifname, const unsigned char *hwaddr, int flags);
extern int ifrename(const char *oldname, const char *newname);
extern int ifdown(const char *ifname, int flags);
extern int ifup(const char *ifname, int flags);
extern int ifhwaddr(const char *ifname, unsigned char *hwaddr);
extern int set_interface_flags(int ifindex, int set, int clear);
extern int get_iface_index(const char *ifname);
extern int set_interface_addr(int ifindex, const unsigned char *hwaddr);
extern int set_interface_name(int ifindex, const char *name);
extern int set_interface_ipaddr(char *ifname, char *ipaddr);
extern int get_ip6_addrprefix(const char *iface, unsigned char *prefix);
extern int eui48to64(unsigned char *mac48, unsigned char *eui64);
extern void closenetlink(void);

/*Radius utilities*/
#define RAD_AUTH_HDR_LEN	20
#define RAD_AUTH_PACKET_LEN	4096
#define RAD_AUTH_TOKEN_LEN	16
#define RAD_MAX_PASS_LEN	128

#define RAD_ATTR_USER_NAME	1	/*string*/
#define RAD_ATTR_USER_PASSWORD	2	/*passwd*/
#define RAD_ATTR_NAS_IP_ADDR	4	/*ip*/
#define RAD_ATTR_NAS_PORT	5	/*int*/
#define RAD_ATTR_SERVICE_TYPE	6	/*int*/
#define RAD_ATTR_ACCTID		44
#define RAD_ATTR_PORT_TYPE	61	/*int*/
#define RAD_ATTR_EAP		79	/*oct*/
#define RAD_ATTR_MESSAGE	80	/*oct*/

enum RADIUS_CODE {
	RAD_CODE_AUTHREQUEST	=	1,
	RAD_CODE_AUTHACCEPT	=	2,
	RAD_CODE_AUTHREJECT	=	3,
	RAD_CODE_ACCTREQUEST	=	4,
	RAD_CODE_ACCTRESPONSE	=	5,
	RAD_CODE_AUTHCHALLENGE	=	11
};

extern unsigned char *addradattr(struct radius_packet *packet, char type, unsigned char *val, char len);
extern void addradattrint(struct radius_packet *packet, char type, unsigned int val);
extern void addradattrip(struct radius_packet *packet, char type, char *ipaddr);
extern void addradattrstr(struct radius_packet *packet, char type, char *str);
extern struct radius_packet *new_radpacket(unsigned char code, unsigned char id);
extern int send_radpacket(struct radius_packet *packet, const char *userpass, radius_cb read_cb, void *cb_data);
extern void add_radserver(const char *ipaddr, const char *auth, const char *acct, const char *secret, int timeout);
extern unsigned char *radius_attr_first(struct radius_packet *packet);
extern unsigned char *radius_attr_next(struct radius_packet *packet, unsigned char *attr);

/*SSL Socket utilities*/
extern void sslstartup(void);
extern void *tlsv1_init(const char *cacert, const char *cert, const char *key, int verify);
extern void *sslv2_init(const char *cacert, const char *cert, const char *key, int verify);
extern void *sslv3_init(const char *cacert, const char *cert, const char *key, int verify);
extern void *dtlsv1_init(const char *cacert, const char *cert, const char *key, int verify);

extern int socketread(struct fwsocket *sock, void *buf, int num);
extern int socketwrite(struct fwsocket *sock, const void *buf, int num);
/*the following are only needed on server side of a dgram connection*/
extern int socketread_d(struct fwsocket *sock, void *buf, int num, union sockstruct *addr);
extern int socketwrite_d(struct fwsocket *sock, const void *buf, int num, union sockstruct *addr);

extern void ssl_shutdown(void *ssl, int sock);
extern void tlsaccept(struct fwsocket *sock, struct ssldata *orig);
extern struct fwsocket *dtls_listenssl(struct fwsocket *sock);
extern void startsslclient(struct fwsocket *sock);

/*config file parsing functions*/
extern void initconfigfiles(void);
extern void unrefconfigfiles(void);
extern int process_config(const char *configname, const char *configfile);
extern struct bucket_loop *get_category_loop(const char *configname);
extern struct bucket_list *get_category_next(struct bucket_loop *cloop, char *name, int len);
extern struct bucket_list *get_config_category(const char *configname, const char *category);
extern struct config_entry *get_config_entry(struct bucket_list *categories, const char *item);
extern void config_file_callback(config_filecb file_cb);
extern void config_cat_callback(struct bucket_list *categories, config_catcb entry_cb);
extern void config_entry_callback(struct bucket_list *entries, config_entrycb entry_cb);

/*Forward Decl*/
/** @brief Forward decleration of structure.*/
typedef struct xml_node xml_node;
/** @brief Forward decleration of structure.*/
typedef struct xml_search xml_search;
/** @brief Forward decleration of structure.*/
typedef struct xml_doc xml_doc;
/** @brief Forward decleration of structure.*/
typedef struct xslt_doc xslt_doc;

/*XML*/
struct xml_attr {
	const char	*name;
	const char	*value;
};

struct xml_node {
	const char		*name;
	const char		*value;
	const char		*key;
	struct bucket_list	*attrs;
	void			*nodeptr;
};

extern struct xml_doc *xml_loaddoc(const char *docfile, int validate);
extern struct xml_doc *xml_loadbuf(const uint8_t *buffer, uint32_t len, int validate);
extern struct xml_node *xml_getfirstnode(struct xml_search *xpsearch, void **iter);
extern struct xml_node *xml_getnextnode(void *iter);
extern struct bucket_list *xml_getnodes(struct xml_search *xpsearch);
extern struct xml_search *xml_xpath(struct xml_doc *xmldata, const char *xpath, const char *attrkey);
extern int xml_nodecount(struct xml_search *xsearch);
extern struct xml_node *xml_getnode(struct xml_search *xsearch, const char *key);
extern const char *xml_getattr(struct xml_node *xnode, const char *attr);
extern void xml_modify(struct xml_doc *xmldoc, struct xml_node *xnode, const char *value);
extern void xml_setattr(struct xml_doc *xmldoc, struct xml_node *xnode, const char *name, const char *value);
extern struct xml_node *xml_addnode(struct xml_doc *xmldoc, const char *xpath, const char *name, const char *value, const char *attrkey, const char *keyval);
void xml_appendnode(struct xml_doc *xmldoc, const char *xpath, struct xml_node *child);
void xml_unlink(struct xml_node *xnode);
extern void xml_delete(struct xml_node *xnode);
extern char *xml_getbuffer(void *buffer);
extern void *xml_doctobuffer(struct xml_doc *xmldoc);
extern const char *xml_getrootname(struct xml_doc *xmldoc);
extern struct xml_node *xml_getrootnode(struct xml_doc *xmldoc);
extern void xml_savefile(struct xml_doc *xmldoc, const char *file, int format, int compress);
extern void xml_createpath(struct xml_doc *xmldoc, const char *xpath);
extern void xml_init();
extern void xml_close();

/*XSLT*/
struct xslt_doc *xslt_open(const char *xsltfile);
void xslt_addparam(struct xslt_doc *xsltdoc, const char *param, const char *value);
void xslt_apply(struct xml_doc *xmldoc, struct xslt_doc *xsltdoc, const char *filename, int comp);
void *xslt_apply_buffer(struct xml_doc *xmldoc, struct xslt_doc *xsltdoc);
void xslt_init();
void xslt_close();

/* LDAP */
enum ldap_starttls {
	LDAP_STARTTLS_NONE,
	LDAP_STARTTLS_ATTEMPT,
	LDAP_STARTTLS_ENFORCE
};

enum ldap_attrtype {
	LDAP_ATTRTYPE_CHAR,
	LDAP_ATTRTYPE_B64,
	LDAP_ATTRTYPE_OCTET
};

struct ldap_rdn {
	const char *name;
	const char *value;
	struct ldap_rdn *next;
	struct ldap_rdn *prev;
};

struct ldap_attrval {
	int	len;
	enum ldap_attrtype type;
	char *buffer;
};

struct ldap_attr {
	const char *name;
	int count;
	struct ldap_attrval **vals;
	struct ldap_attr *next;
	struct ldap_attr *prev;
};

struct ldap_entry {
	const char *dn;
	const char *dnufn;
	int rdncnt;
	struct ldap_rdn **rdn;
	struct ldap_attr *list;
	struct bucket_list *attrs;
	struct ldap_attr *first_attr;
	struct ldap_entry *next;
	struct ldap_entry *prev;
};

struct ldap_results {
	int count;
	struct ldap_entry *first_entry;
	struct bucket_list *entries;
};

/** @brief Forward decleration of structure.*/
typedef struct ldap_conn ldap_conn;
/** @brief Forward decleration of structure.*/
typedef struct ldap_modify ldap_modify;
/** @brief Forward decleration of structure.*/
typedef struct ldap_add ldap_add;

extern struct ldap_conn *ldap_connect(const char *uri, enum ldap_starttls starttls,int timelimit, int limit, int debug, int *err);
extern int ldap_simplebind(struct ldap_conn *ld, const char *dn, const char *passwd);
extern int ldap_saslbind(struct ldap_conn *ld, const char *mech, const char *realm, const char *authcid,
						 const char *passwd, const char *authzid);
extern int ldap_simplerebind(struct ldap_conn *ld, const char *initialdn, const char *initialpw, const char *base, const char *filter,
							 const char *uidrdn, const char *uid, const char *passwd);
extern void ldap_close(struct ldap_conn *ld);

extern const char *ldap_errmsg(int res);

extern struct ldap_results *ldap_search_sub(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...);
extern struct ldap_results *ldap_search_one(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...);
extern struct ldap_results *ldap_search_base(struct ldap_conn *ld, const char *base, const char *filter, int b64enc, int *res, ...);

extern void ldap_unref_entry(struct ldap_results *results, struct ldap_entry *entry);
extern void ldap_unref_attr(struct ldap_entry *entry, struct ldap_attr *attr);
extern struct ldap_entry *ldap_getentry(struct ldap_results *results, const char *dn);
extern struct ldap_attr *ldap_getattr(struct ldap_entry *entry, const char *attr);

extern struct ldap_modify *ldap_modifyinit(const char *dn);
extern int ldap_mod_del(struct ldap_modify *lmod, const char *attr, ...);
extern int ldap_mod_add(struct ldap_modify *lmod, const char *attr, ...);
extern int ldap_mod_rep(struct ldap_modify *lmod, const char *attr, ...);
extern int ldap_domodify(struct ldap_conn *ld, struct ldap_modify *lmod);

extern int ldap_mod_remattr(struct ldap_conn *ldap, const char *dn, const char *attr);
extern int ldap_mod_delattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value);
extern int ldap_mod_addattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value);
extern int ldap_mod_repattr(struct ldap_conn *ldap, const char *dn, const char *attr, const char *value);

/*
 * CURL Bits
 */
struct basic_auth {
	const char *user;
	const char *passwd;
};

struct curlbuf {
	uint8_t *header;
	uint8_t *body;
	char *c_type;
	size_t hsize;
	size_t bsize;
};

/** @brief Forward decleration of structure.*/
typedef struct curl_post curl_post;
typedef struct basic_auth *(*curl_authcb)(const char *user, const char *passwd, void *data);
typedef int (*curl_progress_func)(void*, double, double, double, double);
typedef void(*curl_progress_pause)(void*, int);
typedef void *(*curl_progress_newdata)(void*);

int curlinit(void);
void curlclose(void);
struct basic_auth *curl_newauth(const char *user, const char *passwd);
struct curlbuf *curl_geturl(const char *def_url, struct basic_auth *bauth, curl_authcb authcb,void *data);
void curl_setprogress(curl_progress_func cb, curl_progress_pause p_cb, curl_progress_newdata d_cb, void *data);
void curl_setauth_cb(curl_authcb auth_cb, void *data);
struct curl_post *curl_newpost(void);
void curl_postitem(struct curl_post *post, const char *name, const char *item);
struct curlbuf *curl_posturl(const char *def_url, struct basic_auth *bauth, struct curl_post *post, curl_authcb authcb,void *data);
struct curlbuf *curl_ungzip(struct curlbuf *cbuf);
extern struct xml_doc *curl_buf2xml(struct curlbuf *cbuf);
char *url_escape(char *url);
char *url_unescape(char *url);


/*File Utils*/
int is_file(const char *path);
int is_dir(const char *path);
int is_exec(const char *path);
#ifdef __WIN32__
int mk_dir(const char *dir);
#else
int mk_dir(const char *dir, mode_t mode, uid_t user, gid_t group);
#endif

/*easter egg copied from <linux/jhash.h>*/
/** @addtogroup LIB-Hash
  * @{
  * @brief Default init value for hash function.*/
#define JHASH_INITVAL           0xdeadbeef
/** @brief Define jenhash as hashlittle on big endian it should be hashbig*/
#define jenhash(key, length, initval)   hashlittle(key, length, (initval) ? initval : JHASH_INITVAL);
/** @}*/
/*
 * atomic flag routines for (obj)->flags
 */
#define clearflag(obj, flag) objlock(obj); \
	obj->flags &= ~flag; \
	objunlock(obj)

#define setflag(obj, flag) objlock(obj); \
	obj->flags |= flag; \
	objunlock(obj)

#define testflag(obj, flag) (objlock(obj) | (obj->flags & flag) | objunlock(obj))

/** @ingroup LIB
  * @brief A macro to replace main() with initilization and daemonization code
  * @see framework_flags
  * @see framework_mkcore()
  * @see framework_init()
  * @param progname Descriptive program name.
  * @param name Copyright holders name.
  * @param email Copyright holders email.
  * @param www Web address.
  * @param year Copyright year.
  * @param runfile Application runfile.
  * @param flags Application flags.
  * @param sighfunc Signal handler function.*/
#define FRAMEWORK_MAIN(progname, name, email, www, year, runfile, flags, sighfunc) \
static int  framework_main(int argc, char *argv[]); \
int  main(int argc, char *argv[]) { \
	framework_mkcore(progname, name, email, www, year, runfile, flags, sighfunc); \
	return (framework_init(argc, argv, framework_main)); \
} \
static int  framework_main(int argc, char *argv[])

/** @brief Macro to assign values to char const*/
#define ALLOC_CONST(const_var, val) { \
		char *tmp_char; \
		if (val) { \
			tmp_char = (char*)malloc(strlen(val) + 1); \
			strcpy(tmp_char, val); \
			const_var = (const char*)tmp_char; \
		} else { \
			const_var = NULL; \
		} \
	}

/** @brief Add this macro to a C++ class to add refobj support.
  *
  * This macro defines operator overloads for new/delete and declares
  * a destructor.
  * @note this should not be used with inheritance*/
#define DTS_OJBREF_CLASS(classtype) \
void *operator new(size_t sz) {\
	return objalloc(sz, &classtype::dts_unref_classtype);\
}\
void operator delete(void *obj) {\
}\
static void dts_unref_classtype(void *data) {\
	delete (classtype*)data;\
}\
~classtype()

#endif
