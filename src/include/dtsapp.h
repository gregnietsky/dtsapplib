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

/** @file
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

#include <signal.h>
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <linux/un.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


/** @brief Socket union describing all address types.
  *
  * @ingroup LIB-Sock*/
union sockstruct {
	/** @brief Base socket addr structure.*/
	struct sockaddr sa;
#ifndef __WIN32
	/** @brief Unix sockets.*/
	struct sockaddr_un un;
#endif
	/** @brief IPv4 socket addr structure.*/
	struct sockaddr_in sa4;
	/** @brief IPv6 socket addr structure.*/
	struct sockaddr_in6 sa6;
	/** @brief Sockaddr storage is a "magic" struct been able to hold IPv4 or IPv6.*/
	struct sockaddr_storage ss;
};

/** @brief Forward decleration of structure.
  * @ingroup LIB-Sock-SSL*/
typedef struct ssldata ssldata;

/** @brief Socket flags controling a socket.
  *
  * @ingroup LIB-Sock*/
enum sock_flags {
	/** @brief The socket has been bound and awaiting connections.*/
	SOCK_FLAG_BIND		= 1 << 0,
	/** @brief The socket is going away stop processing in its thread.*/
	SOCK_FLAG_CLOSE		= 1 << 1,
	/** @brief SSL has been requested on this socket dont allow clear read/send.*/
	SOCK_FLAG_SSL		= 1 << 2,
	/** @brief UNIX Domain Socket*/
	SOCK_FLAG_UNIX		= 1 << 3,
	/** @brief Multicast Socket*/
	SOCK_FLAG_MCAST		= 1 << 4
};

/** @brief Options supplied to framework_mkthread all defaults are unset
  * @ingroup LIB-Thread
  * @note this is shifted 16 bits limiting 16 options this maps to high 16 bits of threadopt*/
enum thread_option_flags {
        /** @brief Flag to enable pthread_cancel calls this is not recomended and can lead to memory leaks.*/
        THREAD_OPTION_CANCEL		= 1 << 0,
        /** @brief Create the the thread joinable only do this if you will be joining it cancelable threads are best detached.*/
        THREAD_OPTION_JOINABLE		= 1 << 1,
        /** @brief Return reference to thread this must be unreferenced.*/
        THREAD_OPTION_RETURN		= 1 << 2
};


/** @brief Socket data structure.
  *
  * @ingroup LIB-Sock*/
struct fwsocket {
	/** @brief Socket FD.*/
	int sock;
	/** @brief Socket protocol.*/
	int proto;
	/** @brief Socket type.*/
	int type;
	/** @brief Socket control flags.
	  * @see sock_flags*/
	enum sock_flags flags;
	/** @brief system socket data structure.
	  * @see sockstruct*/
	union sockstruct addr;
	/** @brief SSL structure for encryption.
	  * @see @ref LIB-Sock-SSL*/
	struct ssldata *ssl;
	/** @brief Parent socket if we connected to a server and were spawned.*/
	struct fwsocket *parent;
	/** @brief We are the parent this is a list of spawn.*/
	struct bucket_list *children;
};

/**@brief Configuration category entry
  * @ingroup LIB-INI*/
struct config_entry {
	/**@ brief Item name*/
	const char *item;
	/**@ brief Item value*/
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

/** @ingroup LIB-WIN32
  * @brief Data structure containing interface information
  * @note This is specific to Windows XP SP1+*/
struct ifinfo { 
	/** @brief Interface index required for at least IPv6 multicast support*/
        int idx;
	/** @brief MAC address of interface*/
        const char *ifaddr;  
	/** @brief IPv4 address priorotised by Routed/Reserved/Zeroconf*/
        const char *ipv4addr;
	/** @brief IPv6 address priorised by Local/6in4*/
        const char *ipv6addr;
};

/** @brief Forward decleration of structure.
  * @ingroup LIB-NAT6*/
typedef struct natmap natmap;

/** @brief Forward decleration of structure.
  * @ingroup LIB-RADIUS*/
typedef struct radius_packet radius_packet;

/** @brief Forward decleration of structure.
  * @ingroup LIB-NF-Q*/
typedef struct nfq_queue nfq_queue;

/** @brief Forward decleration of structure.
  * @ingroup LIB-NF-Q*/
typedef struct nfq_data nfq_data;

/** @brief Forward decleration of structure.
  * @ingroup LIB-NF-CT*/
typedef struct nfct_struct nfct_struct;

/** @brief Forward decleration of structure.
  * @ingroup LIB-NF-Q*/
typedef struct nfqnl_msg_packet_hdr nfqnl_msg_packet_hdr;

/*callback function type def's*/

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
typedef void    *(*threadfunc)(void *);

/** @brief Thread signal handler function
  *
  * @ingroup LIB-Thread
  * @see framework_mkthread()
  * @param data Reference of thread data.*/
typedef int     (*threadsighandler)(int, void *);

/** @brief Callback function to register with a socket that will be called when there is data available.
  *
  * @ingroup LIB-Sock
  * @param sock Socket structure data arrived on.
  * @param data Reference to data held by client/server thread.*/
typedef void	(*socketrecv)(struct fwsocket *, void *);

/** @ingroup LIB-OBJ
  * @brief Callback used to clean data of a reference object when it is to be freed.
  * @param data Data held by reference about to be freed.*/
typedef void	(*objdestroy)(void *);

/** @ingroup LIB-OBJ-Bucket
  * @brief Callback used to calculate the hash of a structure.
  * @param data Data or key to calculate hash from.
  * @param key Key if set to non zero data supplied is the key not data.
  * @returns Hash for the Reference.*/
typedef int32_t (*blisthash)(const void *, int);

/** @ingroup LIB-OBJ-Bucket
  * @brief This callback is run on each entry in a list
  * @see bucketlist_callback()
  * @param data Reference held by the list.
  * @param data2 Reference to data supplied when calling bucketlist_callback.*/
typedef void	(*blist_cb)(void *, void *);

/** @brief Calback used when processing config files.
  * @ingroup LIB-INI
  * @param categories Bucket list of categories.
  * @param filename The filename.
  * @param filepath The filepath.*/
typedef void	(*config_filecb)(struct bucket_list *, const char *, const char *);

/** @brief Calback used when processing a category
  * @ingroup LIB-INI
  * @param entries Bucket list containing entries.
  * @param name Category name.*/
typedef void	(*config_catcb)(struct bucket_list *, const char *);

/** @brief Callback used when processing a entry
  * @ingroup LIB-INI
  * @param item Name of the entry.
  * @param value Value of the entry.*/
typedef void	(*config_entrycb)(const char *, const char *);

/** @ingroup LIB-NF-Q*/
typedef uint32_t (*nfqueue_cb)(struct nfq_data *, struct nfqnl_msg_packet_hdr *, char *, uint32_t, void *, uint32_t *, void **);

/** @ingroup LIB-RADIUS
  * @brief Callback to call when response arrives.
  * @param packet Reference to radius packet.
  * @param data Reference to userdata.*/
typedef void	(*radius_cb)(struct radius_packet *, void *);

/** @brief Application control flags
  * @ingroup LIB*/
 enum framework_flags {
	/** @brief Allow application daemonization.*/
	FRAMEWORK_FLAG_DAEMON		= 1 << 0,
	/** @brief Dont print GNU copyright.*/
	FRAMEWORK_FLAG_NOGNU		= 1 << 1,
	/** @brief Create lockfile on daemonize latter
	  *
	  * Its possible you want to call daemonize latter and want the lockfile created then
	  * @note not compatible with FRAMEWORK_FLAG_DAEMON and has no effect FRAMEWORK_FLAG_DAEMON is set.*/
	FRAMEWORK_FLAG_DAEMONLOCK	= 1 << 2
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
void printgnu(const char *pname, int year, const char *dev, const char *email, const char *www);
void daemonize();
int lockpidfile(const char *runfile);
extern struct thread_pvt *framework_mkthread(threadfunc, threadcleanup, threadsighandler, void *data, int flags);
/* UNIX Socket*/
extern struct fwsocket *unixsocket_server(const char *sock, int protocol, int mask, socketrecv read, void *data);
extern struct fwsocket *unixsocket_client(const char *sock, int protocol, socketrecv read, void *data);
/* Test if the thread is running when passed data from thread */
extern int framework_threadok(void);
extern int startthreads(void);
extern void stopthreads(int join);
int thread_signal(int sig);

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
extern struct fwsocket *accept_socket(struct fwsocket *sock);
extern struct fwsocket *sockconnect(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *udpconnect(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *tcpconnect(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *sockbind(int family, int stype, int proto, const char *ipaddr, const char *port, void *ssl, int backlog);
extern struct fwsocket *udpbind(const char *ipaddr, const char *port, void *ssl);
extern struct fwsocket *tcpbind(const char *ipaddr, const char *port, void *ssl, int backlog);
extern void close_socket(struct fwsocket *sock);

int score_ipv4(struct sockaddr_in *sa4, char *ipaddr, int iplen);
int score_ipv6(struct sockaddr_in6 *sa6, char *ipaddr, int iplen);

#ifdef __WIN32
const char *inet_ntop(int af, const void *src, char *dest, socklen_t size);
struct ifinfo *get_ifinfo(const char *iface);
#endif

int inet_lookup(int family, const char *host, void *addr, socklen_t len);

extern void socketclient(struct fwsocket *sock, void *data, socketrecv read, threadcleanup cleanup);
extern void socketserver(struct fwsocket *sock, socketrecv connectfunc, socketrecv acceptfunc, threadcleanup cleanup, void *data);
struct fwsocket *mcast_socket(const char *iface, int family, const char *mcastip, const char *port, int flags);
const char *sockaddr2ip(union sockstruct *addr, char *buf, int len);

/*IP Utilities*/
extern int checkipv6mask(const char *ipaddr, const char *network, uint8_t bits);
extern void ipv4tcpchecksum(uint8_t *pkt);
extern void ipv4udpchecksum(uint8_t *pkt);
extern void ipv4icmpchecksum(uint8_t *pkt);
extern void ipv4checksum(uint8_t *pkt);
extern int packetchecksumv4(uint8_t *pkt);
extern int packetchecksumv6(uint8_t *pkt);
extern int packetchecksum(uint8_t *pkt);
extern void rfc6296_map(struct natmap *map, struct in6_addr *ipaddr, int out);
extern int rfc6296_map_add(char *intaddr, char *extaddr);
const char *cidrtosn(int bitlen, char *buf, int size);
const char *getnetaddr(const char *ipaddr, int cidr, char *buf, int size);
const char *getbcaddr(const char *ipaddr, int cidr, char *buf, int size);
const char *getfirstaddr(const char *ipaddr, int cidr, char *buf, int size);
const char *getlastaddr(const char *ipaddr, int cidr, char *buf, int size);
uint32_t cidrcnt(int bitlen);
int reservedip(const char *ipaddr);
char* ipv6to4prefix(const char *ipaddr);
int check_ipv4(const char* ip, int cidr, const char *test);
void mcast4_ip(struct in_addr *addr);
void mcast6_ip(struct in6_addr *addr);

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
#ifdef IFLA_MACVLAN_MAX
extern int create_kernmac(char *ifname, char *macdev, unsigned char *mac);
#endif
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
extern void eui48to64(unsigned char *mac48, unsigned char *eui64);
extern void closenetlink(void);
extern int ifrename(const char *oldname, const char *newname);
const char *get_ifipaddr(const char *iface, int family);

/*Radius utilities*/
/** @addtogroup LIB-RADIUS
    @{*/
/** @brief Authentification header length.*/
#define RAD_AUTH_HDR_LEN	20

/** @brief Auth packet length*/
#define RAD_AUTH_PACKET_LEN	4096

/** @brief Auth token length*/
#define RAD_AUTH_TOKEN_LEN	16

/** @brief Auth max password length*/
#define RAD_MAX_PASS_LEN	128

/** @brief Radius attribute username.*/
#define RAD_ATTR_USER_NAME	1	/*string*/

/** @brief Radius attribute password.*/
#define RAD_ATTR_USER_PASSWORD	2	/*passwd*/

/** @brief Radius attribute server IP.*/
#define RAD_ATTR_NAS_IP_ADDR	4	/*ip*/

/** @brief Radius attribute server port.*/
#define RAD_ATTR_NAS_PORT	5	/*int*/

/** @brief Radius attribute service type.*/
#define RAD_ATTR_SERVICE_TYPE	6	/*int*/

/** @brief Radius attribute account id.*/
#define RAD_ATTR_ACCTID		44

/** @brief Radius attribute port type.*/
#define RAD_ATTR_PORT_TYPE	61	/*int*/

/** @brief Radius attribute EAP.*/
#define RAD_ATTR_EAP		79	/*oct*/

/** @brief Radius attribute message.*/
#define RAD_ATTR_MESSAGE	80	/*oct*/

/** @brief Radius packet codes.*/
enum RADIUS_CODE {
	/** @brief Radius auth request.*/
	RAD_CODE_AUTHREQUEST	=	1,
	/** @brief Radius auth accept.*/
	RAD_CODE_AUTHACCEPT	=	2,
	/** @brief Radius auth reject.*/
	RAD_CODE_AUTHREJECT	=	3,
	/** @brief Radius accounting request.*/
	RAD_CODE_ACCTREQUEST	=	4,
	/** @brief Radius accounting response.*/
	RAD_CODE_ACCTRESPONSE	=	5,
	/** @brief Radius auth challenge*/
	RAD_CODE_AUTHCHALLENGE	=	11
};
/** @}*/

extern void addradattrint(struct radius_packet *packet, char type, unsigned int val);
extern void addradattrip(struct radius_packet *packet, char type, char *ipaddr);
extern void addradattrstr(struct radius_packet *packet, char type, char *str);
unsigned char *addradattr(struct radius_packet *packet, char type, unsigned char *val, char len);
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
/** @brief Forward decleration of structure.
  * @ingroup LIB-XML*/
typedef struct xml_node xml_node;
/** @brief Forward decleration of structure.
  * @ingroup LIB-XML*/
typedef struct xml_search xml_search;
/** @brief Forward decleration of structure.
  * @ingroup LIB-XML*/
typedef struct xml_doc xml_doc;
/** @brief Forward decleration of structure.
  * @ingroup LIB-XSLT*/
typedef struct xslt_doc xslt_doc;

/*XML*/
/** @brief XML attribute name value pair.
  * @ingroup LIB-XML*/
struct xml_attr {
	/** @brief Name of attribute.*/
	const char	*name;
	/** @brief Value of attribute.*/
	const char	*value;
};

/** @brief Reference to a XML Node
  * @ingroup LIB-XML*/
struct xml_node {
	/** @brief Name of the node.*/
	const char		*name;
	/** @brief Value of the node.*/
	const char		*value;
	/** @brief Attribute key for searching and indexing.*/
	const char		*key;
	/** @brief Bucket list of attributes.*/
	struct bucket_list	*attrs;
	/** @brief Internal libxml2 node pointer.*/
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
/** @addtogroup LIB-LDAP
  * @{*/
/** @brief SSL connection requirements.*/
enum ldap_starttls {
	/** @brief SSL not attempted at all.*/
	LDAP_STARTTLS_NONE,
	/** @brief SSL attempted but not required.*/
	LDAP_STARTTLS_ATTEMPT,
	/** @brief SSL is required.*/
	LDAP_STARTTLS_ENFORCE
};

/** @brief LDAP attribute types.*/
enum ldap_attrtype {
	/** @brief Plain text.*/
	LDAP_ATTRTYPE_CHAR,
	/** @brief Base64 encoded.*/
	LDAP_ATTRTYPE_B64,
	/** @brief Binary data.*/
	LDAP_ATTRTYPE_OCTET
};

/** @brief LDAP Relative distingushed name linked list*/
struct ldap_rdn {
	/** @brief RDN element name.*/
	const char *name;
	/** @brief RDN element value.*/
	const char *value;
	/** @brief Next RDN element*/
	struct ldap_rdn *next;
	/** @brief Previous RDN element*/
	struct ldap_rdn *prev;
};

/** @brief LDAP attribute value.*/
struct ldap_attrval {
	/** @brief Size of buffer.*/
	int	len;
	/** @brief Data type stored in buffer.*/
	enum ldap_attrtype type;
	/** @brief Value buffer.*/
	char *buffer;
};

/** @brief LDAP attirbute.*/
struct ldap_attr {
	/** @brief Name of attribute.*/
	const char *name;
	/** @brief Value count*/
	int count;
	/** @brief Attribute value array.*/
	struct ldap_attrval **vals;
	/** @brief Next attribute.*/
	struct ldap_attr *next;
	/** @brief Previous attribute.*/
	struct ldap_attr *prev;
};

/** @brief LDAP entry.*/
struct ldap_entry {
	/** @brief LDAP distiguished name.*/
	const char *dn;
	/** @brief LDAP user format distingushed name.*/
	const char *dnufn;
	/** @brief RDN element count.*/
	int rdncnt;
	/** @brief RDN element array.*/
	struct ldap_rdn **rdn;
	/** @brief Linked list of attributes.*/
	struct ldap_attr *list;
	/** @brief Bucket list of attributes.*/
	struct bucket_list *attrs;
	/** @brief First attr (head of list).*/
	struct ldap_attr *first_attr;
	/** @brief Next entry.*/
	struct ldap_entry *next;
	/** @brief Previous entry.*/
	struct ldap_entry *prev;
};

/** @brief LDAP results.*/
struct ldap_results {
	/** @brief Number of entries*/
	int count;
	/** @brief Linked list of entries.*/
	struct ldap_entry *first_entry;
	/** @brief Bucket list of entries.*/
	struct bucket_list *entries;
};

/** @brief Forward decleration of structure.*/
typedef struct ldap_conn ldap_conn;
/** @brief Forward decleration of structure.*/
typedef struct ldap_modify ldap_modify;
/** @brief Forward decleration of structure.*/
typedef struct ldap_add ldap_add;
/** @}*/

extern struct ldap_conn *ldap_connect(const char *uri, enum ldap_starttls starttls,int timelimit, int limit, int debug, int *err);
extern int ldap_simplebind(struct ldap_conn *ld, const char *dn, const char *passwd);
extern int ldap_saslbind(struct ldap_conn *ld, const char *mech, const char *realm, const char *authcid,
						 const char *passwd, const char *authzid);
extern int ldap_simplerebind(struct ldap_conn *ld, const char *initialdn, const char *initialpw, const char *base, const char *filter,
							 const char *uidrdn, const char *uid, const char *passwd);
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

/** @addtogroup LIB-CURL
  * @{*/

/** @brief Basic authentification structure.*/
struct basic_auth {
	/** @brief Username.*/
	const char *user;
	/** @brief Password.*/
	const char *passwd;
};

/** @brief Buffer containing the result of a curl transaction.*/
struct curlbuf {
	/** @brief Header buffer*/
	uint8_t *header;
	/** @brief Body buffer*/
	uint8_t *body;
	/** @brief Mime Type*/	
	char *c_type;
	/** @brief Header size*/	
	size_t hsize;
	/** @brief Body size*/	
	size_t bsize;
};

/** @brief Forward decleration of structure.*/
typedef struct curl_post curl_post;

/** @brief Callback to set the authentification ie on error 401
  * @param user Initial username (currently set)
  * @param passwd Initial password (currently set)
  * @param data Reference to data passed.
  * @returns New auth structure to re attempt authentification.*/
typedef struct basic_auth *(*curl_authcb)(const char*, const char*, void*);

/** @brief CURL callback function called when there is progress (CURLOPT_PROGRESSFUNCTION).
  * @param clientp Reference to userdata supplied.
  * @param dltotal Total download bytes.
  * @param dlnow Current bytes downloaded.
  * @param ultotal Total upload bytes.
  * @param ulnow Current upload bytes.
  * @returns Returning a non-zero value from this callback will cause the transfer to abort.*/
typedef int (*curl_progress_func)(void*, double, double, double, double);

/** @brief Callback function to control the progress bar.
  * @param data Reference to userdata supplied.
  * @param state one of 0, 1 or -1 for Pause, Unpause and Close respectfully.*/
typedef void(*curl_progress_pause)(void*, int);

/** @brief Create a new progress data structure
  * @see curl_setprogress()
  *
  * curl_setprogress() allows setting a default progress callback if set it will
  * call a callback to create a new callback progress userdata for the current session.
  * @param data Reference to userdata supplied to curl_setprogress().
  * @returns Reference to userdata to be used in current session.*/
typedef void *(*curl_progress_newdata)(void*);

/** @}*/

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

/** @brief Default init value for hash function
  * @ingroup LIB-Hash
  *
  * easter egg copied from <linux/jhash.h>*/
#define JHASH_INITVAL           0xdeadbeef

/** @brief Define jenhash as hashlittle on big endian it should be hashbig
  *
  * @ingroup LIB-Hash*/
#define jenhash(key, length, initval)   hashlittle(key, length, (initval) ? initval : JHASH_INITVAL);

/** @ingroup LIB-OBJ
  * @brief Atomically clear a flag in the flags field of a referenced object*/
#define clearflag(obj, flag) \
objlock(obj);\
obj->flags &= ~flag;\
objunlock(obj)

/** @ingroup LIB-OBJ
  * @brief Atomically set a flag in the flags field of a referenced object*/
#define setflag(obj, flag) \
objlock(obj);\
obj->flags |= flag; \
objunlock(obj)

/** @ingroup LIB-OBJ
  * @brief Atomically test a flag in the flags field of a referenced object*/
#define testflag(obj, flag) \
(objlock(obj) | (obj->flags & flag) | objunlock(obj))

/** @ingroup LIB
  * @brief A macro to replace main() with initilization and daemonization code
  * @note Argument count is argc and arguments is array argv.
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

/** @brief Macro to assign values to char const
  * @ingroup LIB*/
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

/** @ingroup LIB-OBJ
  * @brief Add this macro to a C++ class to add refobj support.
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

#ifdef __cplusplus
}
#endif
#endif
