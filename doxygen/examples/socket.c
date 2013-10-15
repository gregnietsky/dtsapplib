#include <string.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <dtsapp.h>

/** @file
  * @brief  Echo server using 1 server and 2 clients.
  *
  * Simple implementation of a echo server shoeing  the network socket
  * interface it creates 1 server and 2 client threads the server echos
  * back what is sent. the sockets support ipv4 and ipv6 and can be UDP or TCP
  * with or without TLS/SSL support.\n
  * On application start using FRAMEWORK_MAIN a licence banner is displayed no 
  * flags are set as i wish to daemonize after checking the command line arguments.\n
  * There is a run/lock file created failure to lock this file prevents execution.\n
  * Once the sockets are created and threads started i sleep the main thread for 5
  * seconds before exiting the system will make sure all threads stop before leaving.\n
  * As you can see the progam initiliztion and flow has been greatly simplified by having
  * these tasks managed.
*/

/** @brief This function does nothing and is here for completeness.
  *
  * When a new connection is recieved this function will be executed
  * to allow processing of the connection.
  * @param sock Reference to new socket
  * @param data Reference to data suppled on thread start*/
void accept_func(struct fwsocket *sock, void *data) {
}

/** @brief Server thread data is available.
  *
  * This function executes when the server socket has data to read the
  * socket will need to be read from using socketread[_d] socketread_d is
  * a wrapper arround recvfrom and socketwerite_d is a wrapper arround sendto
  * this is important when dealing with un encrypted UDP sessions where the 
  * socket needs sendto addresss to send data too.
  * @param sock Reference to socket data is available on.
  * @param data Reference to data held by thread.*/
void server_func(struct fwsocket *sock, void *data) {
	char buff[128];
	union sockstruct addr;

	if (socketread_d(sock, &buff, 128, &addr) > 0) {
		socketwrite_d(sock, &buff, strlen(buff) + 1, &addr);
		printf("[S] %s %i\n", buff, sock->sock);
		sleep(1);
	}
}

/** @brief client thread data is available.
  *
  * There is no need to worry about UDP support in client
  * trhead callbacks and use of socketread  / socketwrite
  * is all that is required.
  * @param sock Reference to socket data is available on.
  * @param data Reference to data held by thread.*/
void client_func(struct fwsocket *sock, void *data) {
	char buff[128];

	if (socketread(sock, &buff, 128) > 0) {
		socketwrite(sock, &buff, strlen(buff) + 1);
		printf("[C] %s %i\n", buff, sock->sock);
	}
}

/** @brief Bassed on the options create server and clients.
  *
  * @li If SSL / TLS was requested create SSL/TLS sessions to use.
  * @li Bind to server and connect the clients.
  * @li Start threads.
  * @li Send data to server.
  * @li Sleep
  *
  * @param ipaddr As supplied on the command line
  * @param tcp Set to non zero if using TCP.
  * @param ssl Set to non zero if TLS/SSL is required.*/
void socktest(const char *ipaddr, int tcp, int ssl) {
	struct fwsocket *serv, *client, *client2;
	void *ssl_c = NULL, *ssl_s = NULL, *ssl_c2 = NULL;
	char *buff = "client 1";
	char *buff2 = "client 2";
	int cnt;

	if (ssl && tcp) {
		ssl_s = sslv3_init("certs/cacert.pem", "certs/server-cert.pem", "certs/server-key.pem", SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE);
		ssl_c = sslv3_init("certs/cacert.pem", "certs/client-cert.pem", "certs/client-key.pem", SSL_VERIFY_NONE);
		ssl_c2 = sslv3_init("certs/cacert.pem", "certs/client-cert.pem", "certs/client-key.pem", SSL_VERIFY_NONE);
	} else if (ssl) {
		ssl_s = dtlsv1_init("certs/cacert.pem", "certs/server-cert.pem", "certs/server-key.pem", SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE);
		ssl_c = dtlsv1_init("certs/cacert.pem", "certs/client-cert.pem", "certs/client-key.pem", SSL_VERIFY_NONE);
		ssl_c2 = dtlsv1_init("certs/cacert.pem", "certs/client-cert.pem", "certs/client-key.pem", SSL_VERIFY_NONE);
	}

	if (tcp) {
		serv = tcpbind(ipaddr, "1111", ssl_s, 10);
		client = tcpconnect(ipaddr, "1111", ssl_c);
		client2 = tcpconnect(ipaddr, "1111", ssl_c2);
	} else {
		serv = udpbind(ipaddr, "1111", ssl_s);
		client = udpconnect(ipaddr, "1111", ssl_c);
		client2 = udpconnect(ipaddr, "1111", ssl_c2);
	}

	if (serv && client && client2) {
		socketserver(serv, server_func, accept_func, NULL, NULL);
		socketclient(client, NULL, client_func, NULL);
		socketclient(client2, NULL, client_func, NULL);

		socketwrite(client, buff, strlen(buff)+1);
		socketwrite(client2, buff2, strlen(buff2)+1);

		sleep(5);
	} else {
		printf("ERROR\n");
	}

	close_socket(client);
	close_socket(client2);
	close_socket(serv);
}

/** @brief Initialise the application under the library replacing main()
  *
  * @see FRAMEWORK_MAIN()
  * @see framework_mkcore()
  * @see framework_init()
  */
/*![main]*/
FRAMEWORK_MAIN("Socket Client/Server Echo (TCP/TLS/UDP/DTLS)", "Gregory Hinton Nietsky", "gregory@distrotech.co.za",
        "http://www.distrotech.co.za", 2013, "/var/run/sockettest", 0, NULL) {
	if (argc < 3) {
		printf("Requires arguments %s [tcp|tls|udp|dtls] ipaddr\n", argv[0]);
		return (-1);
	}
	daemonize();
/*![main]*/

	if (!strcmp(argv[1], "udp")) {
		socktest(argv[2], 0, 0);
	} else if (!strcmp(argv[1], "dtls")) {
		socktest(argv[2], 0, 1);
	} else if (!strcmp(argv[1], "tcp")) {
		socktest(argv[2], 1, 0);
	} else if (!strcmp(argv[1], "tls")) {
		socktest(argv[2], 1, 1);
	} else {
		printf("Invalid Option\n");
	}
}
