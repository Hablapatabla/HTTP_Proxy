#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/ioctl.h>
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
#include "rmessage.h"

#define BUFSIZE 8192
#define CACHESIZE 30
#define ONEHOUR 3600
#define STARTOFCACHEFIELD "Cache-Control: "
#define STARTOFCACHE " "
#define ENDOFCACHE " "
#define FAIL -1
#define MAXSOCKETS 1024 * 10

const char *create_key_command_template = "openssl genrsa -out certificates/key.%s.key 2048";

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
	char hostname[512];
	SSL_CTX *ctx;
	SSL *ssl;
} Socket_Context;

Socket_Context *socket_contexts[MAXSOCKETS] = {NULL};

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
		memcpy(bigBuf + total, babyBuf, message_size);
		total += message_size;
	} while (message_size == BUFSIZE);
  close(sockfd);
	*size = total;
  return bigBuf;
}

void handle_get(Request *r, char *request, int client_sfd) {
  int message_size = 0;
	printf("in handle get\n");
  char *server_response = get_response(r, request, &message_size);
	//printf("got response %d long: \n%s\n", message_size, server_response);
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
  //if(find_client_sfd(sockfd))
  //  free_client(find_client_sfd(sockfd));
  close(sockfd);
  FD_CLR(sockfd, set);
}

int create_tunnel(Request *r) {
	int sockfd;
	struct sockaddr_in server_addr;
  struct hostent *server;
	char *hostname = r->host;
	unsigned short port = r->port;

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
	makeKey(hostname);
	makeCSR(hostname);
	makeCSRExtension(hostname);
	signCSR(hostname);
	convertCertificateToPem(hostname);
	cleanupCSR(hostname);
}

SSL_CTX *InitClientCTX() {
	const SSL_METHOD *method = TLSv1_2_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	return ctx;
}

SSL_CTX *InitServerCTX() {
	const SSL_METHOD *method = TLSv1_2_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char *hostname)
{
	char *certificate_name_template = "certificates/cert.%s.pem";
	char *key_name_template = "certificates/key.%s.pem";
	char cert_name[BUFSIZE];
	char key_name[BUFSIZE];

	sprintf(cert_name, certificate_name_template, hostname);
	sprintf(key_name, key_name_template, hostname);


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

// https://stackoverflow.com/questions/31171396/openssl-non-blocking-socket-ssl-read-unpredictable
char *SAFE_SSL_read(SSL *ssl, int *ssl_read) {
	char buf[BUFSIZE];
	char bufCopy[BUFSIZE];
	int total_read = 0;
	int bytes = 0;
	fd_set fds;
  struct timeval timeout;
	char *request = calloc(BUFSIZE, sizeof(char));

	printf("\n --- Beginning SAFE_SSL_read --- \n");
	if (ssl) {
		while (1) {
			bytes = SSL_read(ssl, buf, BUFSIZE);
			if (bytes > 0) {
				request = realloc(request, total_read + BUFSIZE);
				memcpy(&request[total_read], buf, bytes);
				total_read += bytes;
				printf("\n\n --- SAFE_SSL_read %d bytes: --- \n\n", bytes);
				if (buf[bytes-1] == '\n' && buf[bytes-3] == '\n' && buf[0] != 'H') {
					printf("\n --- NEW LINES DETECTED --- \n");
					break;
				}


				//if (bytes < BUFSIZE)
				//	break;
			}
			else {
				printf("\n\n --- SAFE_SSL_read IN ERROR --- \n\n\n");
				int err = SSL_get_error(ssl, bytes);
				switch (err)
				{
					case SSL_ERROR_NONE:
						continue;
					case SSL_ERROR_ZERO_RETURN:
					{
						//peer disconnected
						printf("SSL ERROR ZERO RETURN\n");
						break;
					}
					case SSL_ERROR_WANT_READ:
					{
						printf("SSL ERROR WANT READ\n");
						int sock = SSL_get_rfd(ssl);
            FD_ZERO(&fds);
            FD_SET(sock, &fds);

            timeout.tv_sec = 3;
            timeout.tv_usec = 0;

            err = select(sock+1, &fds, NULL, NULL, &timeout);
            if (err > 0) {
								printf("IN SELECT \n");
								FD_ZERO(&fds);
                continue; // more data to read...
							}
            else if (err == 0) {
                printf("TIMED OUT WANT READ\n");
            }

            break;
					}
					case SSL_ERROR_WANT_WRITE:
					{
						printf("SSL ERROR WANT WRITE\n");
						int sock = SSL_get_rfd(ssl);
            FD_ZERO(&fds);
            FD_SET(sock, &fds);

            timeout.tv_sec = 0;
            timeout.tv_usec = 500000;

            err = select(sock+1, &fds, NULL, NULL, &timeout);
            if (err > 0)
                continue; // more data to read...
            else if (err == 0) {
                printf("TIMED OUT WANT WRITE\n");
            }

            break;
					}
					default:
					{
						printf("ERROR DEFAULTING OUT\n");
						break;
					}
				}
				//break;
			}
		}
	}
	*ssl_read = total_read;
	printf("\n --- End SAFE_SSL_read --- \n");
	return request;
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

int main(int argc, char *argv[]) {
int master_socket, rv;
//int client_socket, message_size;
socklen_t client_size;
char remoteIP[INET6_ADDRSTRLEN];
int yes = 1;
struct sockaddr_storage client_addr;

char buf[BUFSIZE];

if(argc != 2) {
fprintf(stderr, "usage: %s <port>\n", argv[0]);
exit(1);
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

freeaddrinfo(ai);

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
      printf("selectserver: new connection from %s on "
                                              "socket %d\n",
            inet_ntop(client_addr.ss_family,
              get_in_addr((struct sockaddr*)&client_addr),
                                              remoteIP, INET6_ADDRSTRLEN),
            new);
          }
        }
      else {
				// Data coming from a socket that is not a member of a tunnel
				if (!socket_contexts[i]) {
					printf("NO SOCKET CONTEXTS\n");
					int bytes_read = 0;
					char *TCP_buf = TCP_read(i, &bytes_read);
					printf("FINISHED TCP READ\nREAD %d BYTES: \n%s\n", bytes_read, TCP_buf);
					if (!TCP_buf) {
						fprintf(stderr, "TCP_read returned NULL\n");
						close(i);
						FD_CLR(i, &master_set);
					}
					else {
						for (int j = 0; j < bytes_read; j++) {
							int sor = 0;
							if(TCP_buf[j] == '\n' && TCP_buf[j + 2] == '\n') {
								printf("In break point\n\n");
								char *TCP_request = calloc(bytes_read, sizeof(char));
								if (!TCP_request)
									error("Calloc failed\n");

								strncpy(TCP_request, &TCP_buf[sor], j + 3);
								fprintf(stderr, "TCP REQUEST: \n%s\n", TCP_request);
								Request *R = parse_request(TCP_request);
								if (R == NULL) {
									fprintf(stderr, "R IS NULL\n");
									write(i, "HTTP/1.1 400 Bad Request\r\nConnection: Closed\r\n\r\n", 54);
								}
								else if(strncmp(R->method, "GET", 3) == 0) {
									fprintf(stderr, "BEFORE GET\n");
									handle_get(R, TCP_request, i);
								}
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

										if (SSL_accept(serv_ssl) <= 0) {
											ERR_print_errors_fp(stderr);
											printf("ACCEPT ERROR :/ \n");
											exit(1);
										}
										if (SSL_connect(client_ssl) <= 0) {
											ERR_print_errors_fp(stderr);
											printf("CONNECT ERROR :/ \n");
											exit(1);
										}
										printf("WE DID IT!!!!\n");
										exit(1);

									}
									else {
										write(i, "HTTP/1.1 400 Bad Connect\r\nConnection: Closed\r\n\r\n", 54);
									}
								}
								else {
									write(i, "HTTP/1.1 400 Bad Request\r\nConnection: Closed\r\n\r\n", 54);
									fprintf(stderr, "BAD REQUEST\n");
								}

								if (R)
									free_r(R);
								sor = j + 3;
								free(TCP_request);
							}
						}
						free(TCP_buf);
					}
				}
				/*
          if ((nbytes = read(i, buf, BUFSIZE)) <= 0) {
              if(nbytes == 0) {
                  //Connection closed
                  //printf("selectserver: socket %d hung up\n", i);
              }
              else {
                  perror("read err: ");
              }
              close(i);
              FD_CLR(i, &master_set);
              int partner = findPartner(i);
              if(FD_ISSET(i, &server_set)) {
                  FD_CLR(i, &server_set);
                  if((partner = findPartner(i)) != -1) {
                      remTunnel(partner, i);
                  }
              }
              else if(FD_ISSET(i, &client_set)) {
                  FD_CLR(i, &client_set);
                  if((partner = findPartner(i)) != -1) {
                      remTunnel(i, partner);
                  }
              }
          }
          else {
              //We have data!!!
              //Two types of Data: HTTPS and HTTP
              //If HTTPS TODO
              //Else Below
              char * bigBuf = (char *) calloc(BUFSIZE, sizeof(char));
              int totalSize = nbytes;
              memcpy(bigBuf, buf, nbytes);
              while(nbytes == BUFSIZE) {
                  if((nbytes = recv(i, buf, sizeof buf, 0)) > 0){
                      bigBuf = (char *) realloc(bigBuf, totalSize + BUFSIZE);
                      memcpy(&bigBuf[totalSize], buf, nbytes);
                      totalSize += nbytes;
                  }
              }
              //All Data read to this point
              int partner;
              if((partner = findPartner(i)) != -1) {
								int l = 0;
                  if((l =send(partner, bigBuf, totalSize, 0)) == -1) {
                      perror("send");
                  }
              }
              else {
                  if(!FD_ISSET(i, &client_set)) {
                      FD_SET(i, &client_set);
                  }
                  for (int j = 0; j < totalSize; j++) {
                      int sor = 0;
                      if(bigBuf[j] == '\n' && bigBuf[j + 2] == '\n'){
                          char req[BUFSIZE + 1] = { 0 };
                          strncpy(req, &bigBuf[sor], j + 3);
                          Request *R = parse_request(req);
													if (R == NULL) {
															write(i, "HTTP/1.1 400 Bad Request\r\nConnection: Closed\r\n\r\n", 54);
													}
                          else if(strncmp(R->method, "CONNECT", 7) == 0) {
                              int newServ = create_tunnel(R);
															if (newServ != -1) {
	                              FD_SET(newServ, &server_set);
																FD_SET(newServ, &master_set);
																if (newServ > fdmax)
																	fdmax = newServ;
	                              addTunnel(i, newServ);
																makeCertificateAndKey(R->host);
																write(i, "HTTP/1.1 200 Connection Established\r\n\r\n", 43);
																if(strcmp(R->host, "www.google.com") == 0) {
																	SSL_CTX *serv_ctx = InitServerCTX();
																	LoadCertificates(serv_ctx, R->host);
																	SSL *serv_ssl = SSL_new(serv_ctx);
																	SSL *ssl = SSL_new(serv_ctx);
																	SSL_set_fd(serv_ssl, i);
																	int ssl_read = 0;
																	if (SSL_accept(serv_ssl) <= 0) {
																		ERR_print_errors_fp(stderr);
																		printf("ACCEPT ERROR :/ \n");
																		exit(1);
																	}
																	else {
																		char *sslrequest = SAFE_SSL_read(serv_ssl, &ssl_read);
																		printf("\n\n ---- FINAL REQUEST ---- \n\n%s\n\n", sslrequest);
																		SSL_CTX *ctx = InitClientCTX();
																		SSL *ssl = SSL_new(ctx);
																		SSL_set_fd(ssl, newServ);
																		if (sslrequest && SSL_connect(ssl) <= 0) {
																			ERR_print_errors_fp(stderr);
																			printf("ACCEPT ERROR :/ \n");
																			exit(1);
																		}
																		else {
																			int q = SSL_write(ssl, sslrequest, ssl_read);
																			char *sslresponse = SAFE_SSL_read(ssl, &ssl_read);
																			if (sslresponse) {
																				printf("\n\n ---- FINAL RESPONSE ---- \n\n%s\n\n", sslresponse);
																				q = SSL_write(serv_ssl, sslresponse, ssl_read);
																				free(sslresponse);
																			}
																			printf("\n\n\nABOUT TO FREE STUFF\n\n\n");
																			free(sslrequest);
																			SSL_shutdown(serv_ssl);
																			SSL_free(serv_ssl);
																			SSL_shutdown(ssl);
																			SSL_free(ssl);
																			SSL_CTX_free(ctx);
																			SSL_CTX_free(serv_ctx);
																		}

																	}
																}
															}
                          }
                          else if(strncmp(R->method, "GET", 3) == 0) {
                              handle_get(R, req, i);
                          }
                          else {
                              perror("Invalid HTTP Method for Proxy!");
                          }
													if (R)
                          	free_r(R);
                          sor = j + 3;
                      }
                  }
              }
              free(bigBuf);
          }
        }*/
	      }
	    }
		}
	}
  destroyTunnels();
	EVP_cleanup();
  return 0;
}
