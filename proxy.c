#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include <openssl/rsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "parse.h"

#define BUFSIZE 1024 * 16
#define CACHESIZE 30
#define ONEHOUR 3600
#define STARTOFCACHEFIELD "Cache-Control: "
#define STARTOFCACHE " "
#define ENDOFCACHE " "
#define FAIL -1
#define MAXSOCKETS 1024 * 10

const char *create_key_command_template = "openssl genrsa -out certificates/key.%s.key 2048 2>/dev/null";

const char *key_name_change_template = "mv certificates/key.%s.key certificates/key.%s.pem";

const char *key_file_name_template = "certificates/key.%s.pem";

const char *create_csr_template = "openssl req -new -key certificates/key.%s.pem -subj \"/C=US/ST=/L=/O=/CN=%s\" -out certificates/%s.csr";

const char *extension_file_content_template =
"authorityKeyIdentifier=keyid,issuer\n" \
"basicConstraints=CA:FALSE\n" \
"keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n" \
"subjectAltName = @alt_names\n\n" \
"[alt_names]\n\n" \
"DNS.1 = %s\n" \
"DNS.2 = www.%s\n";

const char *extension_file_name_template = "certificates/v%s.ext";

const char *sign_command_first_serial_template = "openssl x509 -req -in certificates/%s.csr -extfile certificates/v%s.ext -CA myCA.pem -CAkey myCA.key -passin pass:abcd -CAcreateserial -out certificates/cert.%s.crt -days 365";

const char *sign_command_not_first_serial_template = "openssl x509 -req -in certificates/%s.csr -extfile certificates/v%s.ext -CA myCA.pem -CAkey myCA.key -passin pass:abcd -CAserial myCA.srl -out certificates/cert.%s.crt -days 365";

const char *cert_name_change_template = "mv certificates/cert.%s.crt certificates/cert.%s.pem";

const char *remove_csr_template = "rm certificates/%s.csr";

const char *certificate_name_template = "certificates/cert.%s.pem";


typedef struct CacheElement {
	char *data, *url;
	int max_age, port, size;
	time_t entry_time, last_retrieval_time;
} CacheElement;

struct connTunnel {
    int clientfd;
    int serverfd;
    struct connTunnel *next;
};

struct connTunnel *root = NULL;

typedef struct Socket_Context {
	int partner_tcp_sfd;
	SSL_CTX *ctx;
	SSL *ssl;
} Socket_Context;

Socket_Context *socket_contexts[MAXSOCKETS] = {NULL};
char *connected_hostnames[MAXSOCKETS] = { NULL };

void addTunnel_H(int cfd, int sfd, struct connTunnel **t) {
    if(*t == NULL) {
        *t = (struct connTunnel*) malloc(sizeof(struct connTunnel));
        (*t)->clientfd = cfd;
        (*t)->serverfd = sfd;
        (*t)->next = NULL;
    }
    else {
        addTunnel_H(cfd, sfd, &(*t)->next);
    }
}

void addTunnel(int cfd, int sfd) {
    addTunnel_H(cfd, sfd, &root);
}

void remTunnel_H(int cfd, int sfd, struct connTunnel **t,
                                  struct connTunnel *prev) {
    if(*t == NULL) {
        return;
    }
    else if((*t)->clientfd == cfd || (*t)->serverfd == sfd) {
        if(prev != NULL) {
            prev->next = (*t)->next;
            free(*t);
            *t = NULL;
        }
        else {
            struct connTunnel *temp = (*t)->next;
            free(*t);
            *t = temp;
        }
    }
    else {
        remTunnel_H(cfd, sfd, &(*t)->next, *t);
    }
}

void remTunnel(int cfd, int sfd) {
    remTunnel_H(cfd, sfd, &root, NULL);
}

int findPartner_H(int fd, struct connTunnel **t){
    if(*t == NULL){
        return -1;
    }
    else if((*t)->clientfd == fd){
        return (*t)->serverfd;
    }
    else if((*t)->serverfd == fd){
        return (*t)->clientfd;
    }
    else {
        return findPartner_H(fd, &(*t)->next);
    }
}

int findPartner(int fd) {
    return findPartner_H(fd, &root);
}

void destroyTunnels_H(struct connTunnel **t) {
    if(*t != NULL) {
        destroyTunnels_H(&(*t)->next);
        close((*t)->clientfd);
        close((*t)->serverfd);
        free(*t);
    }
}

void destroyTunnels() {
    destroyTunnels_H(&root);
}

int noTunnels() {
    if(root == NULL) {
        return 1;
    }
    else {
        return 0;
    }
}

void error(char *msg) {
perror(msg);
exit(1);
}

//Free struct data allocated on heap by strdup in main
void erase_elements(CacheElement e) {
	free(e.data);
	free(e.url);
}

void clean_string(char *str) {
  int len = strlen(str);
  for(int i = 0; i < len; ++i) {
    if(str[i] == '\r' || str[i] == '\n')
      str[i] = ' ';
  }
}


int is_cached(char *url, CacheElement *cache, int num_stored, int port)
{
  int index;
  for(index = 0; index < num_stored; index++) {
    if((strcmp(url, cache[index].url) == 0) && (port == cache[index].port))
      return index;
  }
  return -1;
}

/*
 * Function: find_expired(CE c[])
 * Desc: Finds an expired element in a cache and returns the index of the found
 * element. If no element is found, return -1
 * Returns: Index of expired element, or -1
 */
int find_expired(CacheElement cache[]) {
	time_t current_time = time(NULL);
	for(int i = 0; i < CACHESIZE; ++i) {
		CacheElement e = cache[i];
		double time_since_creation = difftime(current_time, e.entry_time);
		if(time_since_creation > e.max_age)
			return i;
	}
	return -1;
}


/*
 * Function: find_oldest(CE c[])
 * Desc: Finds the index of the oldest-accessed element in a cache. If an
 * element has never been accessed, that element will be returned immediately.
 * Returns: Index of found element
 */
int find_oldest(CacheElement cache[]) {
	if(cache[0].last_retrieval_time != -1) {
		time_t oldest = cache[0].last_retrieval_time;
		int oldest_index = 0;
		double difference;
		for(int i = 1; i < CACHESIZE; ++i) {
			if(cache[i].last_retrieval_time != -1) {
				difference = difftime(cache[i].last_retrieval_time, oldest);
				if(difference > 0) {
					oldest = cache[i].last_retrieval_time;
					oldest_index = i;
				}
			} else
				return i;
		}
		return oldest_index;
	} else
		return 0;
}


/*
 * Function: cache_insert(CE **c, CE *e, int *s)
 * Desc: Inserts an element into a cache. Prioritizes a vacant cache slot, then
 * an expired cache element, then the oldest cache element.
 * Args: **c = Pointer to a cache
 *        *e = Pointer to the cache element to be inserted
 *        *s = Pointer to the index denoting how many cache slots are full
 */
void cache_insert(CacheElement **c, CacheElement *e, int *stored)
{
  if(*stored < CACHESIZE) {
    (*c)[*stored] = *e;
    (*stored)++;
    return;
  }
  int expired_index = find_expired(*c);
  if(expired_index == -1) {
    int oldest_element = find_oldest(*c);
    erase_elements((*c)[oldest_element]);
    (*c)[oldest_element] = *e;
  } else {
    erase_elements((*c)[expired_index]);
    (*c)[expired_index] = *e;
  }
}


//Updates the last retrieval time of a cache element to the current time
void update_retrieved(CacheElement **c, int index)
{
  time_t curr_time = time(NULL);
  (*c)[index].last_retrieval_time = curr_time;
}
/*
 * Function: get_attribute(char *b, int o, char **f, int n)
 * Desc: Parses an attribute out of an HTTP message
 * Args: *b = String containing a well-formatted HTTP message
 *       off = Integer for offset of last string token
 *       **f = Array of fields needed for parsing
 *       num = Length of **f
 * Returns: A heap-allocated C string containing the desired attribute.
 *          It is the client's responsibility to free this C string.
 *          Returns NULL if attribute could not be found.
 */
char *get_attribute(char *buffer, int offset, char *fields[], int num_fields)
{
  char *tokens[num_fields];
  tokens[0] = strstr(buffer, fields[0]);
  if(tokens[0] == NULL)
    return NULL;
  for(int i = 1; i < num_fields; ++i) {
    if(i == num_fields - 1)
      tokens[i] = strstr(tokens[i - 1] + offset, fields[i]);
    else
      tokens[i] = strstr(tokens[i - 1], fields[i]);
  }

  char attribute[(tokens[num_fields - 1] - tokens[num_fields - 2])];
  strncpy(attribute, tokens[num_fields - 2] + 1,
        tokens[num_fields - 1] - tokens[num_fields - 2]);
  attribute[sizeof(attribute) - 1] = '\0';
  char *return_attr = strdup(attribute);
  return return_attr;
}
/*
 * Function: parse_age(char *b)
 * Desc: Searches for a Cache-control header in an HTTP response. If a header
 * is found, returns the value defined at max-age=[value]. If no header is
 * found, one hour is returned.
 * Returns: Age in seconds.
 */
int parse_age(char *buf)
{
  int len = strlen(buf);
  char cleaned[len + 1];
  strcpy(cleaned, buf);
  clean_string(cleaned);
  cleaned[len] = '\0';

  char *age_fields[3] = {STARTOFCACHEFIELD, STARTOFCACHE, ENDOFCACHE};
  char *age = get_attribute(cleaned, 2, age_fields, 3);
  if(age == NULL) {
    free(age);
    return ONEHOUR;
  }
  else {
    int age_d = ONEHOUR;
    sscanf(age, "max-age=%d", &age_d);
    free(age);
    return age_d;
  }
}

/*
 * Function: refresh_element(CE **c, int i, char *r, int p)
 * Desc: Updates the cache element at index i within the cache. Takes a fresh
 * HTTP response and determines what the cache age should be. Updates all other
 * relevant fields.
 */
void refresh_element(CacheElement **c, int index, char *response, int size,
																																int port)
{
  int age = parse_age(response);
  time_t curr_time = time(NULL);
  (*c)[index].entry_time = curr_time;
  (*c)[index].max_age = age;
  (*c)[index].last_retrieval_time = -1;
  (*c)[index].data = response;
  (*c)[index].port = port;
	(*c)[index].size = size;
}


char *get_response(Request *r, char *request, int *size) {
  int sockfd, message_size;
  struct sockaddr_in server_addr;
  struct hostent *server;

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    error("Error opening socket (get_response)\n");

  if((server = gethostbyname(r->host)) == NULL)
    error("Error getting hostname (get_response)\n");

  bzero((char *) &server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,
	  (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(r->port);

  if(connect(sockfd, (struct sockaddr *)&server_addr,
                                                  sizeof(server_addr)) < 0)
    error("Error connecting (get_response)\n");
  if((message_size = write(sockfd, request, strlen(request))) < 0)
    error("Error writing (get_response)\n");

	char *bigBuf = calloc(2*BUFSIZE + 1, sizeof(char));
	if(!bigBuf)
	  error("Error callocing buffer (get_response)\n");
	char babyBuf[BUFSIZE];
	int total = 0, bigBufCapacity = (2*BUFSIZE + 1);

	do {
		message_size = read(sockfd, babyBuf, BUFSIZE);
		if (message_size < 0) {
			printf("Error occured: %d\n", message_size);
		}
		else if (message_size == 0) {
			printf("Disconnect\n");
		}
		if (total + message_size > bigBufCapacity) {
			bigBufCapacity = bigBufCapacity * 2;
			bigBuf = realloc(bigBuf, bigBufCapacity);
			if (!bigBuf)
				error("Error reallocing bigBuf\n");
		}
		memcpy(&bigBuf[total], babyBuf, message_size);
		total += message_size;
	} while (message_size == BUFSIZE);
  close(sockfd);
	*size = total;
  return bigBuf;
}

void handle_get(Request *r, char *request, int client_sfd) {
  int message_size = 0;
  char *server_response = get_response(r, request, &message_size);
  if((message_size = write(client_sfd, server_response,
                                message_size)) < 0)
      error("Error writing to socket\n");
	free(server_response);
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void empty_message(int sockfd, fd_set *set) {
  close(sockfd);
  FD_CLR(sockfd, set);
}

int create_tunnel(Request *r) {
	int sockfd;
	struct sockaddr_in server_addr;
  struct hostent *server;
	char *hostname = r->host;
	unsigned short port = r->port;
	sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);

  if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    return -1;

  if((server = gethostbyname(r->host)) == NULL)
    return -1;

  bzero((char *) &server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr,
	  (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(r->port);

  if(connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    return -1;

  return sockfd;
}

void makeKey(char *hostname) {
	char command[BUFSIZE] = {0};
	sprintf(command, create_key_command_template, hostname);
	system(command);

	memset(command, 0, BUFSIZE);
	sprintf(command, key_name_change_template, hostname, hostname);
	system(command);
}

void makeCSR(char *hostname) {
	char command[BUFSIZE] = {0};
	sprintf(command, create_csr_template, hostname, hostname, hostname);
	system(command);
}

void makeCSRExtension(char *hostname) {
	char extfile[BUFSIZE];
	sprintf(extfile, extension_file_content_template, hostname, hostname);

	char extfilename[BUFSIZE];
	sprintf(extfilename, extension_file_name_template, hostname);

	FILE *ext_fp = fopen(extfilename, "w");
	if (ext_fp == NULL) {
		fprintf(stderr, "\nCould not create extension file\n");
	}
	else {
		fprintf(ext_fp, "%s", extfile);
	}
	fclose(ext_fp);
}

void signCSR(char *hostname) {
	static int first_serial = 0;
	char command[BUFSIZE] = {0};

	if (first_serial == 0) {
	 	first_serial++;
		sprintf(command, sign_command_first_serial_template, hostname, hostname, hostname);
	}
	else
		sprintf(command, sign_command_not_first_serial_template, hostname, hostname, hostname);

	system(command);
}

void convertCertificateToPem(char *hostname) {
	char command[BUFSIZE] = {0};

	sprintf(command, cert_name_change_template, hostname, hostname);
	system(command);
}


void cleanupCSR(char *hostname) {
	char command[BUFSIZE] = {0};

	sprintf(command, remove_csr_template, hostname, hostname);
	system(command);
}

/*
 * This logic uses the const char * templates at the top of the file.
 */
void makeCertificateAndKey(char *hostname) {
	char buf[BUFSIZE];
	sprintf(buf, certificate_name_template, hostname);
	if (access(buf, F_OK) == 0) {
		memset(buf, 0 , BUFSIZE);
	 	sprintf(buf, key_file_name_template, hostname);
		if (access(buf, F_OK) == 0) {
			return;
		}
	}
	makeKey(hostname);
	makeCSR(hostname);
	makeCSRExtension(hostname);
	signCSR(hostname);
	convertCertificateToPem(hostname);
	cleanupCSR(hostname);
}

SSL_CTX *InitClientCTX() {
	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	return ctx;
}

SSL_CTX *InitServerCTX() {
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char *hostname)
{
	char cert_name[BUFSIZE];
	char key_name[BUFSIZE];

	sprintf(cert_name, certificate_name_template, hostname);
	sprintf(key_name, key_file_name_template, hostname);

	if ( SSL_CTX_use_certificate_file(ctx, cert_name, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		error("Error use certificate file\n");
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, key_name, SSL_FILETYPE_PEM) <= 0 ) {
			ERR_print_errors_fp(stderr);
			error("Error use private key\n");
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) ) {
			fprintf(stderr, "Private key does not match the public certificate\n");
			error("error check private key\n");
	}
}

/*
 * Function: custom_wait(int s, int n)
 * Desc: Sleeps for the given quantity of seconds + nanoseconds using nanosleep.
 * Args: int s = # of seconds to wait
 *       int n = # of nanoseconds to wait
 */
void custom_wait(int sec, int nsec) {
  struct timespec ts;
  int status;
  ts.tv_sec = sec;
  ts.tv_nsec = nsec;
  do {
    status = nanosleep(&ts, &ts);
  } while (status && errno == EINTR);
}

char *TCP_read(int sockfd, int *bytes_read) {
	char buf[BUFSIZE];
	int nbytes = 0;
	if ((nbytes = read(sockfd, buf, BUFSIZE)) <= 0) {
		return NULL;
	}

	char *bigBuf = calloc(BUFSIZE, sizeof(char));
	if (!bigBuf)
		error("Calloc failed\n");
	int totalSize = nbytes;
	memcpy(bigBuf, buf, nbytes);
	while(nbytes == BUFSIZE) {
			if((nbytes = read(sockfd, buf, BUFSIZE)) > 0) {
					bigBuf = (char *) realloc(bigBuf, totalSize + BUFSIZE);
					memcpy(&bigBuf[totalSize], buf, nbytes);
					totalSize += nbytes;
			}
			else if (nbytes < 0) {
				free(bigBuf);
				return NULL;
			}
	}
	*bytes_read = totalSize;
	return bigBuf;
}

void display_ssl_error(int err) {
	switch (err)
	{
		case SSL_ERROR_NONE:
			printf("\n --- SSL_ERROR_NONE --- \n");
			break;
		case SSL_ERROR_ZERO_RETURN:
		{
			printf("\n --- SSL ERROR ZERO RETURN - CLOSING TUNNEL --- \n");
			break;
		}
		case SSL_ERROR_WANT_READ:
		{
			printf("\n --- SSL ERROR WANT READ --- \n");
			break;
		}
		case SSL_ERROR_WANT_WRITE:
		{
			printf("\n --- SSL ERROR WANT WRITE --- \n");
			break;
		}
		case SSL_ERROR_WANT_CONNECT:
		{
			printf("\n --- SSL ERROR WANT CONNECT --- \n");
			break;
		}
		case SSL_ERROR_WANT_ACCEPT:
		{
			printf("\n --- SSL ERROR WANT ACCEPT --- \n");
			break;
		}
		case SSL_ERROR_WANT_X509_LOOKUP:
		{
			printf("\n --- SSL ERROR WANT X509 LOOKUP --- \n");
			break;
		}
		case SSL_ERROR_WANT_ASYNC:
		{
			printf("\n --- SSL_ERROR_WANT_ASYNC --- \n");
			break;
		}
		case SSL_ERROR_WANT_ASYNC_JOB:
		{
			printf("\n --- SSL_ERROR_WANT_ASYNC_JOB --- \n");
			break;
		}
		case SSL_ERROR_WANT_CLIENT_HELLO_CB:
		{
			printf("\n --- SSL_ERROR_WANT_CLIENT_HELLO_CB --- \n");
			break;
		}
		case SSL_ERROR_SYSCALL:
		{
			printf("\n --- SSL_ERROR_SYSCALL ERRNO: %d --- \n", errno);
			break;
		}
		case SSL_ERROR_SSL:
		{
			printf("\n --- SSL_ERROR_SSL --- \n");
			error("SSL_ERROR_SSL");
			break;
		}
		default:
		{
			printf("\n --- DEFAULT ERROR: %d --- \n", err);
			break;
		}
	}
}

Socket_Context *newSocketContext(int fd, SSL_CTX *ctx, SSL *ssl) {
	Socket_Context *s = malloc(sizeof(struct Socket_Context));
	if (!s)
		error("Error malloc'ing socket context\n");
	s->partner_tcp_sfd = fd;
	s->ctx = ctx;
	s->ssl = ssl;
	return s;
}

void handshakeError(SSL *ssl, int r) {
	ERR_print_errors_fp(stderr);
	int err = SSL_get_error(ssl, r);
	display_ssl_error(err);
}

void cleanupTunnelsSSL(SSL_CTX *sctx, SSL *sssl, SSL_CTX *cctx, SSL *cssl) {
	if (sctx)
		SSL_CTX_free(sctx);
	if (sssl)
		SSL_free(sssl);
	if (cctx)
		SSL_CTX_free(cctx);
	if (cssl)
		SSL_free(cssl);
}

void cleanupTunnelsTCP(int cfd, int sfd, fd_set *set) {
	close(cfd);
	close(sfd);
	FD_CLR(cfd, set);
	FD_CLR(sfd, set);
}


void close_ssl_tunnel(int fd, int partner, fd_set *set) {
	SSL *ssla = socket_contexts[fd]->ssl;
	SSL *sslb = socket_contexts[partner]->ssl;
	SSL_CTX *ctxa = socket_contexts[fd]->ctx;
	SSL_CTX *ctxb = socket_contexts[partner]->ctx;
	SSL_shutdown(ssla);
	SSL_shutdown(sslb);
	cleanupTunnelsSSL(ctxa, ssla, ctxb, sslb);
	close(fd);
	close(partner);
	FD_CLR(fd, set);
	FD_CLR(partner, set);

	free(socket_contexts[fd]);
	free(socket_contexts[partner]);
	if (connected_hostnames[fd]) {
		free(connected_hostnames[fd]);
		connected_hostnames[fd] = NULL;
	}
	if (connected_hostnames[partner]) {
		free(connected_hostnames[partner]);
		connected_hostnames[partner] = NULL;
	}
	socket_contexts[fd] = NULL;
	socket_contexts[partner] = NULL;
}


int proxyBlock(char* h, char* c){
	char host[256];
	char cat[100];
	if(c == NULL) {
		return 0;
	}
	strcpy(host, h);
	strcat(host, "\n");
	strcpy(cat, c);
	char buf[256];
	FILE* p = fopen("proxyBlock.txt", "r");
	if(p == NULL) {
		error("File Couldn't Be Opened!\n");
	}
	if(strcmp(cat, "All") == 0) {
		while(fgets(buf, 256, p) != NULL){
			if(strcmp(buf, host) == 0) {
				return 1;
			}
		}
		return 0;
	}
	else {
		strcat(cat, "\n");
		int catFound = 0;
		while(fgets(buf, 256, p) != NULL) {
			if(strcmp(buf, cat) == 0) {

				catFound = 1;
			}
			if(catFound == 1) {
				if(strcmp(buf, host) == 0) {
					return 1;
				}
				else {
					if(strcmp(buf, "\n") == 0) {
						return 0;
					}
				}
			}

		}
		return 0;
	}
	fclose(p);
}




int main(int argc, char *argv[]) {
int master_socket, rv;
//int client_socket, message_size;
socklen_t client_size;
char remoteIP[INET6_ADDRSTRLEN];
int yes = 1;
struct sockaddr_storage client_addr;

char buf[BUFSIZE];

char* proxyFlg = NULL;

if(argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <port> <contentBlock>\n", argv[0]);
        exit(1);
}
else if(argc == 3) {
	proxyFlg = (char *) malloc(100 * sizeof(char));
	strcpy(proxyFlg, argv[2]);
}

// Most of this boilerplate is taken from beej's select server example.
// http://beej.us/guide/bgnet/html
struct addrinfo hints;
struct addrinfo *ai, *p;

memset(&hints, 0, sizeof hints);
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
hints.ai_flags = AI_PASSIVE;
rv = getaddrinfo(NULL, argv[1], &hints, &ai);
if(rv != 0)
error("Server: Error with getaddrinfo\n");

for(p = ai; p != NULL; p = p->ai_next) {
	master_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
	if(master_socket < 0)
	  continue;
	setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

	if(bind(master_socket, p->ai_addr, p->ai_addrlen) < 0) {
	  close(master_socket);
	  continue;
	}
	break;
}

if(p == NULL)
error("Server: Failed to bind\n");

//freeaddrinfo(ai);

if(listen(master_socket, 10) < 0)
error("Server: Error listening\n");

fd_set master_set, temp_set, server_set, client_set;

FD_ZERO(&master_set);
FD_ZERO(&temp_set);
FD_SET(master_socket, &master_set);

int fdmax = master_socket;
int nbytes;

SSL_library_init();
SSL_load_error_strings();
OpenSSL_add_all_algorithms();

while(1) {
temp_set = master_set;
if(select(fdmax+1, &temp_set, NULL, NULL, NULL) < 0)
  error("Server: Error with Select");
//Boilerplate taken from:
//https://www.gnu.org/software/libc/manual/html_node/Server-Example.html
for (int i = 0; i <= fdmax; ++i) {
  if (FD_ISSET(i, &temp_set)) {
    if (i == master_socket) {
      /* Connection request on original socket. */
      int new;
      client_size = sizeof client_addr;
      new = accept (master_socket,
                    (struct sockaddr *) &client_addr, &client_size);
      if (new < 0)
        error ("Server: error with accept\n");
      else {
        FD_SET(new, &master_set);
        if(new > fdmax)
          fdmax = new;
          }
        }
      else {
				// Data coming from a socket that is not a member of a tunnel
				if (!socket_contexts[i]) {
					int bytes_read = 0;
					char *TCP_buf = TCP_read(i, &bytes_read);
					if (!TCP_buf) {
						close(i);
						FD_CLR(i, &master_set);
					}
					else {
						for (int j = 0; j < bytes_read; j++) {
							int sor = 0;
							if(TCP_buf[j] == '\n' && TCP_buf[j + 2] == '\n') {
								char TCP_request[BUFSIZE + 1] = { 0 };
								strncpy(TCP_request, &TCP_buf[sor], j + 3);
								Request *R = parse_request(TCP_request);

								if (R == NULL)
									write(i, "HTTP/1.1 400 Bad Request\r\nConnection: Closed\r\n\r\n", 54);
								else if(proxyBlock(R->host, proxyFlg))
									write(i, "HTTP/1.1 403 Forbidden\r\nProxy Blocked\r\n\r\n", 42);
								else if(strncmp(R->method, "GET", 3) == 0)
									handle_get(R, TCP_request, i);
								else if(strncmp(R->method, "CONNECT", 7) == 0) {
									int server_fd = create_tunnel(R);
									if (server_fd != -1) {
										FD_SET(server_fd, &master_set);
										if (server_fd > fdmax)
											fdmax = server_fd;
										makeCertificateAndKey(R->host);
										write(i, "HTTP/1.1 200 Connection Established\r\n\r\n", 43);

										SSL_CTX *serv_ctx = InitServerCTX();
										LoadCertificates(serv_ctx, R->host);
										SSL *serv_ssl = SSL_new(serv_ctx);
										SSL_set_fd(serv_ssl, i);

										SSL_CTX *client_ctx = InitClientCTX();
										SSL *client_ssl = SSL_new(client_ctx);
										SSL_set_fd(client_ssl, server_fd);

										int accept = SSL_accept(serv_ssl);
										if (accept <= 0) {
											handshakeError(serv_ssl, accept);
											cleanupTunnelsSSL(serv_ctx, serv_ssl, NULL, NULL);
											cleanupTunnelsTCP(i, server_fd, &master_set);
										}
										else
										{
											int connect = SSL_connect(client_ssl);
											if (connect <= 0) {
												SSL_shutdown(serv_ssl);
												handshakeError(client_ssl, connect);
												cleanupTunnelsSSL(serv_ctx, serv_ssl, client_ctx, client_ssl);
												cleanupTunnelsTCP(i, server_fd, &master_set);
											}
											else {
												Socket_Context *serv_socket_ctx = newSocketContext(server_fd, serv_ctx, serv_ssl);
												Socket_Context *client_socket_ctx = newSocketContext(i, client_ctx, client_ssl);

												socket_contexts[i] = serv_socket_ctx;
												socket_contexts[server_fd] = client_socket_ctx;
												connected_hostnames[server_fd] = strdup(R->host);
												struct timeval tv;
												tv.tv_sec = 0;
												tv.tv_usec = 500000; // Half second timeout
												setsockopt(i, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
												setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
											}
										}
									}
									else {
										write(i, "HTTP/1.1 400 Bad Connect\r\nConnection: Closed\r\n\r\n", 54);
									}
								}
								else if (strncmp(R->method, "LIST", 4) == 0) {
									char host_buf[100];
									for (int j = 0; j < MAXSOCKETS; ++j) {
										if (connected_hostnames[j] != NULL) {
											strncat(host_buf, connected_hostnames[j], 100);
											write(i, host_buf, 100);
											memset(host_buf, 0, 100);
										}
									}
									if (socket_contexts[i] != NULL)
										exit(1);
									close(i);
									FD_CLR(i, &master_set);
								}
								else
									write(i, "HTTP/1.1 400 Bad Request\r\nConnection: Closed\r\n\r\n", 54);
								if (R)
									free_r(R);
								sor = j + 3;
							}
						}
						if (TCP_buf != NULL)
							free(TCP_buf);
					}
				}
				else {
					if (!socket_contexts[i]->ssl)
						error("SSL * IS NULL IN SOCKET CONTEXTS\n");
					else {
						int partner = socket_contexts[i]->partner_tcp_sfd;
						int read = SSL_read(socket_contexts[i]->ssl, buf, BUFSIZE);
						if (read <= 0) {
							ERR_print_errors_fp(stderr);
							int err = SSL_get_error(socket_contexts[i]->ssl, read);
							if (err == SSL_ERROR_ZERO_RETURN)
								close_ssl_tunnel(i, partner, &master_set);
						}
						else {

							printf("\n --- SSL READ %d BYTES --- \n%s\n", read, buf);

							int wrote = SSL_write(socket_contexts[partner]->ssl, buf, read);
							if (wrote <= 0) {
								ERR_print_errors_fp(stderr);
								int err = SSL_get_error(socket_contexts[partner]->ssl, wrote);
								display_ssl_error(err);
								if (err == SSL_ERROR_ZERO_RETURN)
									close_ssl_tunnel(i, partner, &master_set);
							}
						 }
						}
					}
	      }
	    }
		}
	}
	EVP_cleanup();
  return 0;
}
