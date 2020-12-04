#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <openssl/bio.h> /* BasicInput/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include <openssl/rsa.h>

#include "parse.h"
#include "rmessage.h"

#define BUFSIZE 8192
#define CACHESIZE 30
#define ONEHOUR 3600
#define STARTOFCACHEFIELD "Cache-Control: "
#define STARTOFCACHE " "
#define ENDOFCACHE " "

#define FAIL -1
#define YEAR 31536000L


typedef struct CacheElement {
	char *data, *url;
	int max_age, port, size;
	time_t entry_time, last_retrieval_time;
} CacheElement;

typedef struct connTunnel {
    int clientfd;
    int serverfd;
		SSL *client_ssl;
		SSL *serv_ssl;
    struct connTunnel *next;
} connTunnel;

connTunnel *root = NULL;
const char *privateKey = "-----BEGIN PRIVATE KEY-----\n"\
"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDhjFZAntvICtiJ\n"\
"v6G5f754/b6YilCDNNoF+odvxh30YNsG/AEp1NXHmLav3hzsmnzOENaM+KWKWjLm\n"\
"v5FoGz3/QihxkObvDjqQxDdf4cYP2kB8/zuutdKUjPGykD6VIqtb/5X43w82J8Xl\n"\
"GwJrOxrZMev/UJmc3QL6Iweo87SFSzSDfjNYSRG0bhqtLXmZC9rVXKfZnzSYaCpd\n"\
"pJu+ZRsFyQ64pP37qdvzjj6/Pa5y+8zH4g5LcJ1eHwj4OyjHl85eDR5Zw1nA+L47\n"\
"e6//des4YaFPHj5TMYmd7D/ARVcLqSIOJrYKj8FtGN+KEZe0SK7tSv9GCP7qJKjp\n"\
"qEkc9NihAgMBAAECggEBAJRv4pf2tJgroyTMzGejjbxc6qHDbYdcMhx7K8VA8pfR\n"\
"YnRvR2i7XNJWS+zkVc7VQUvwwvLV9URfZl58Nvr36s5iQPG0tncfuyVpLTRaBxqJ\n"\
"vaVF6IZrvSHsvGiTC8zkmzgZth6q1n0CoffM1cOyi1Hjy/gkmGQnA/2RLkpf0S9i\n"\
"+Wme8xIL3D76/geEoKf5HNhMN6TISDU2T3Tzs6/R0W28HRZFdQNfn/fdTCPF3r03\n"\
"2RwldkFUUhwiDA5bsntP7Srj3xt2kmlBs8gA7+PEKoJ7WtPjsq4G4TkpBf5xh5Mp\n"\
"OBXTWy9HkGf6JZ++xhV8QAoy5/awv9vMEgSE5McCXRECgYEA/ljI61ZTFmCNsbin\n"\
"219YjUafqWVhG9S2n+NE39x8fE4lNNjGQcnksJN2inC/f9xBb3FAkjoLwKdE6k9u\n"\
"qeuYRfe2FtdYX2RSEd6UTkFhRGtJK5xrPiSgzciVPVrWe/WHy7AVE4zmdQ/MwJaO\n"\
"HQNMztrnaB8wYCjFAUvS667Mh/UCgYEA4wOiGZGuYxvyI5RAbxa5c/+ux21K6tJK\n"\
"ooPN68KhzBifEXUQrIgphG7n4fqpQhSDeNZQ2AU/Ke5jgWeBP1auO5KtXaLZ0QXY\n"\
"Vy4BAW4wlPquJhvV/I6XSnX/fCV84AhQVqDbfezMH4l7sIqb3m2pm4Db745a/PJv\n"\
"ptpyRAJw3n0CgYAjWQtzSWf6sCiBDnyljDauS6Zc0G4ShBltVxR3WBkk3WdmVMoY\n"\
"0oop0BSlYM38YwvlBQRITjDb8WMufSOQEeHzt11jB0KM31BYk2phBc0SySY+HVr6\n"\
"I/UFJF85S6qLR7A7qpkDQo20ryFxknrlpVPDW8DVQ6BhfMkESRljD8P1EQKBgQDe\n"\
"4p1Pz2nRYwm9BvywVTZl/p5CrTrGDQw8PX57QFANDAt5X1+slc91eFJw2+M8vtlK\n"\
"VdlwDs6yQ50s20vZvSg500wlyBNllwCOr9tK5T4Lt4guYFwbqIBAGlRqNoBBkcgX\n"\
"Fb4LB+ht+lUXwy9AFplU1RKbREBvYzReNNHFlkPtHQKBgQC2UapnfRD2QWI1oD3V\n"\
"zwE+g471o+8JLZ4OxyOqlunYWrXRjHd7XVdrMOT/HeapzV6bM/Wc04gVd+VfZYzu\n"\
"VtubW1aryWuITJzkUc64HwYFx6UWteTXaebRINnqhr8xi23IXsD7PQudv+mu+aYq\n"\
"5ODgYdjC646wKBMCXxRqGb7w4w==\n"\
"-----END PRIVATE KEY-----\n\0";

void addTunnel_H(int cfd, int sfd, SSL *cssl, SSL *sssl,struct connTunnel **t) {
    if(*t == NULL) {
        *t = (struct connTunnel*) malloc(sizeof(struct connTunnel));
        (*t)->clientfd = cfd;
        (*t)->serverfd = sfd;
				(*t)->client_ssl = cssl;
				(*t)->serv_ssl = sssl;
        (*t)->next = NULL;
    }
    else {
        addTunnel_H(cfd, sfd, cssl, sssl, &(*t)->next);
    }
}

void addTunnel(int cfd, int sfd, SSL *cssl, SSL *sssl) {
    addTunnel_H(cfd, sfd, cssl, sssl, &root);
}

void remTunnel_H(int cfd, int sfd, struct connTunnel **t,
                                  struct connTunnel *prev) {
    if(*t == NULL) {
        return;
    }
    else if((*t)->clientfd == cfd || (*t)->serverfd == sfd) {
        if(prev != NULL) {
            prev->next = (*t)->next;
						if ((*t)->client_ssl)
							SSL_free((*t)->client_ssl);
						if ((*t)->serv_ssl)
							SSL_free((*t)->serv_ssl);
            free(*t);
            *t = NULL;
        }
        else {
            struct connTunnel *temp = (*t)->next;
						if ((*t)->client_ssl)
							SSL_free((*t)->client_ssl);
						if ((*t)->serv_ssl)
							SSL_free((*t)->serv_ssl);
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

int findPartner_H(int fd, int *which, struct connTunnel **t){
    if(*t == NULL){
        return -1;
    }
    else if((*t)->clientfd == fd){
				*which = 0;
        return (*t)->serverfd;
    }
    else if((*t)->serverfd == fd){
				*which = 1;
        return (*t)->clientfd;
    }
    else {
        return findPartner_H(fd, which, &(*t)->next);
    }
}

int findPartner(int fd, int *which) {
    return findPartner_H(fd, which, &root);
}

connTunnel *findTunnel(int fd) {
	connTunnel *temp = root;
	if (!temp)
		return NULL;
	if (!temp->next && temp->clientfd != fd && temp->serverfd != fd)
		return NULL;

	while (temp && temp->clientfd != fd && temp->serverfd != fd)
		temp = temp->next;
	return temp;
}

void destroyTunnels_H(struct connTunnel **t) {
    if(*t != NULL) {
        destroyTunnels_H(&(*t)->next);
        close((*t)->clientfd);
        close((*t)->serverfd);
				SSL_free((*t)->client_ssl);
				SSL_free((*t)->serv_ssl);
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
  static CacheElement *cache = NULL;
  static int initialized = 0;
  static int num_cached = 0;
  int message_size = 0;

  if (!initialized) {
    cache = calloc(CACHESIZE, sizeof(*cache));
    initialized++;
  }
  int index = is_cached(r->url, cache, num_cached, r->port);
  if (index == -1) {
    char *server_response = get_response(r, request, &message_size);
    time_t creation_time = time(NULL);
    int age = parse_age(server_response);
    CacheElement e = { .max_age = age, .entry_time = creation_time,
      .last_retrieval_time = -1, .data = server_response,
      .url = strdup(r->url), .port = r->port, .size = message_size};
    cache_insert(&cache, &e, &num_cached);
		//free(server_response);
    if((message_size = write(client_sfd, server_response,
                                message_size)) < 0)
        error("Error writing to socket\n");
  }
  else {
    time_t curr_time = time(NULL);
    if (difftime(curr_time, cache[index].entry_time) < cache[index].max_age) {
      update_retrieved(&cache, index);
      if((message_size = write(client_sfd, cache[index].data,
                                            cache[index].size)) < 0)
          error("Error writing to socket\n");
    }
    else {
			char *server_response = get_response(r, request, &message_size);
      refresh_element(&cache, index, server_response, message_size, r->port);
      if((message_size = write(client_sfd, server_response,
                                  message_size)) < 0)
          error("Error writing to socket\n");
    }
  }
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

SSL_CTX *InitServerCTX() {
	SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLSv1_2_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		error("Error with creating context.\n");
	}
	return ctx;
}

void LoadCertificates(SSL_CTX *ctx, char *cert, char *key) {
	/* set the local certificate from CertFile */
if ( SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		error("Error use certificate file\n");
}
/* set the private key from KeyFile (may be the same as CertFile) */
if ( SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		error("Error use private key\n");
}
/* verify private key */
if ( !SSL_CTX_check_private_key(ctx) ) {
		fprintf(stderr, "Private key does not match the public certificate\n");
		error("error check private key\n");
}
}

SSL_CTX *InitClientCTX() {
	SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLSv1_2_client_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		error("Error with creating client context.\n");
	}
	return ctx;
}

int mkcert(X509 **x509p, X509 *real_cert, EVP_PKEY **pkeyp, int bits, int serial, int days) {
	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();

	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf((void *)privateKey, -1);
	if (keybio == NULL)
		printf("ERROR WITH MAKING KEYBIO\n");
	rsa = PEM_read_bio_RSAPrivateKey(keybio, rsa, NULL, NULL);

	if (!EVP_PKEY_assign_RSA(pkey,rsa)) {
		printf("ERROR WITH EVP PKEY ASSIGN\n");
		return -1;
	}
	rsa=NULL;

	X509 *cert = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), YEAR);

	X509_set_pubkey(cert, pkey);

	X509_NAME *real_name = X509_get_subject_name(real_cert);
	char *CN;
	for (int i = 0; i < X509_NAME_entry_count(real_name); i++) {
		X509_NAME_ENTRY *e = X509_NAME_get_entry(real_name, i);
		ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
		CN = ASN1_STRING_data(d);
		printf("STR: %s\n", CN);
	}
	X509_set_subject_name(cert, X509_get_subject_name(real_cert));
	printf("AFTER SUBJECT?\n");
	X509_NAME *issuer = X509_NAME_new();
	X509_NAME_add_entry_by_txt(issuer, "C", MBSTRING_ASC,
							(unsigned char *)"US", -1, -1, 0);
	X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC,
							(unsigned char *)"proxy_cert", -1, -1, 0);
	for (int i = 0; i < X509_NAME_entry_count(issuer); i++) {
		X509_NAME_ENTRY *e = X509_NAME_get_entry(issuer, i);
		ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
		char *s = ASN1_STRING_data(d);
		printf("STR2: %s\n", s);
	}
	X509_set_issuer_name(cert, issuer);
	printf("AFTER ISSUE?\n");
	X509_sign(cert, pkey, EVP_sha1());
	*x509p = cert;
	*pkeyp = pkey;
	printf("AFER SIGN\n");

	FILE * f;
	f = fopen("testkey.pem", "wb");
	PEM_write_PrivateKey(
	    f,                  /* write the key to the file we've opened */
	    pkey,               /* our key from earlier */
	    NULL, /* default cipher for encrypting the key on disk */
	    NULL,       /* passphrase required for decrypting the key on disk */
	    10,                 /* length of the passphrase string */
	    NULL,               /* callback for requesting a password */
	    NULL                /* data to pass to the callback */
	);
	fclose(f);

	f = fopen("testcert.pem", "wb");
	PEM_write_X509(
	    f,   /* write the certificate to the file we've opened */
	    cert /* our certificate */
	);
	printf("AFTER ALL???\n");
	fclose(f);
	return 1;
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
int nbytes, which;

SSL_library_init();
OpenSSL_add_all_algorithms();
SSL_load_error_strings();

SSL_CTX *serv_ctx = InitServerCTX();
SSL_CTX *client_ctx = InitClientCTX();

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
          int partner;
          if((partner = findPartner(i, &which)) != -1) {
							printf("i=%d\n", i);
							int l = 0;
							memset(buf, 0, BUFSIZE);
							connTunnel *tunnel = findTunnel(i);
							if (which == 0) {
								printf("READING FROM CLIENT: %d\n", i);
								l = SSL_read_ex(tunnel->serv_ssl, buf, BUFSIZE, &nbytes);
								printf("NUMBYTES: %d\n", nbytes);
								//buf[nbytes] = '\0';
								//printf("BUF: %s\n", buf);
							}
							else if (which == 1) {
								printf("READING FROM SERV: %d\n", partner);
								l = SSL_read_ex(tunnel->client_ssl, buf, BUFSIZE, &nbytes);
							}
							if (nbytes <= 0) {
								if(nbytes == 0) {
	                  //Connection closed
	                  printf("selectserver: socket %d hung up\n", i);
	              }
	              else {
	                  perror("read err: ");
	              }
	              close(i);
	              FD_CLR(i, &master_set);
	              int partner = findPartner(i, &which);
	              if(FD_ISSET(i, &server_set)) {
	                  FD_CLR(i, &server_set);
	                  if((partner = findPartner(i, &which)) != -1) {
	                      remTunnel(partner, i);
	                  }
	              }
	              else if(FD_ISSET(i, &client_set)) {
	                  FD_CLR(i, &client_set);
	                  if((partner = findPartner(i, &which)) != -1) {
	                      remTunnel(i, partner);
	                  }
	              }
							}
							else {
								if (which == 0) {
									l = SSL_write(tunnel->client_ssl, buf, nbytes);
									if (l > 0)
										printf("SUCCESSFUL WRITE1\n");
								}
								else if (which == 1){
									l = SSL_write(tunnel->serv_ssl, buf, nbytes);
									if (l > 0)
										printf("SUCCESSFUL WRITE2\n");
								}
							}
							//bigBuf[totalSize] = '\0';
							//printf("BUF: %s\n", bigBuf);
          }
          else {
							//We have data!!!
							//Two types of Data: HTTPS and HTTP
							//If HTTPS TODO
							//Else Below
							if ((nbytes = read(i, buf, BUFSIZE)) <= 0) {
              if(nbytes == 0) {
                  //Connection closed
                  printf("selectserver: socket %d hung up\n", i);
              }
              else {
                  perror("read err: ");
              }
              close(i);
              FD_CLR(i, &master_set);
              int partner = findPartner(i, &which);
              if(FD_ISSET(i, &server_set)) {
                  FD_CLR(i, &server_set);
                  if((partner = findPartner(i, &which)) != -1) {
                      remTunnel(partner, i);
                  }
              }
              else if(FD_ISSET(i, &client_set)) {
                  FD_CLR(i, &client_set);
                  if((partner = findPartner(i, &which)) != -1) {
                      remTunnel(i, partner);
                  }
              }
          }
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
							printf("BUF: %s\nSIZE: %d\n", bigBuf, totalSize);
							//All Data read to this point
              if(!FD_ISSET(i, &client_set)) {
                  FD_SET(i, &client_set);
              }
              for (int j = 0; j < totalSize; j++) {
                  int sor = 0;
                  if(bigBuf[j] == '\n' && bigBuf[j + 2] == '\n'){
											if (totalSize > BUFSIZE + 1) {
												printf("BIG TIME ERRORR\n\n\nSIZE > BUFSIZE\n\n\n");
											}
                      char req[BUFSIZE + 1] = { 0 };
                      strncpy(req, &bigBuf[sor], j + 3);
                      Request *R = parse_request(req);
											if (R == NULL) {
													write(i, "HTTP/1.1 400 Bad Request\r\nConnection: Closed\r\n\r\n", 54);
											}
                      else if(strncmp(R->method, "CONNECT", 7) == 0) {
													printf("HOSTNAME: %s\n", R->host);
													printf("URL: %s\n", R->url);
                          int newServ = create_tunnel(R);
													if (newServ != -1) {
                            FD_SET(newServ, &server_set);
														FD_SET(newServ, &master_set);
														if (newServ > fdmax)
															fdmax = newServ;
													}
													else {
														printf("BIG ERROR\n");
														exit(1);
													}
													SSL *client_ssl = SSL_new(client_ctx);
													SSL_set_connect_state(client_ssl);
													SSL_set_fd(client_ssl, newServ);
													if ( SSL_connect(client_ssl) == FAIL ) { /* perform the connection */
														ERR_print_errors_fp(stderr);
														printf("SSL CONNECT ERRROR\n");
													}
													else {
														printf("CONNECTED!~!!!!\n");
														X509 *cert = SSL_get_peer_certificate(client_ssl);

														write(i, "HTTP/1.1 200 Connection Established\r\nProxy-agent: TrevProx\r\n\r\n", 68);
														/*X509_NAME *subj = X509_get_subject_name(cert);
														char *CN;
														for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
															X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, i);
															ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
															CN = ASN1_STRING_data(d);
															printf("STR: %s\n", CN);
														}
														*/
														X509 *spoofed_cert = NULL;
														EVP_PKEY *key = NULL;
														int q = mkcert(&spoofed_cert, cert, &key, 2048, 0, 365);
														if (q == 1) {
															printf("?\n");
															LoadCertificates(serv_ctx, "testcert.pem", "testkey.pem");
															SSL *serv_ssl = SSL_new(serv_ctx);
															SSL_set_accept_state(serv_ssl);
															SSL_set_fd(serv_ssl, i);
															printf("!\n");
															if (SSL_accept(serv_ssl) <= 0) { /* perform the connection */
																ERR_print_errors_fp(stderr);
																printf("SSL ACCEPT ERRROR2\n");
															} else {
																printf("HOLYYYY SHITTTTT\nserv id: %d", newServ);
																addTunnel(i, newServ, client_ssl, serv_ssl);
															}
														}
													}
                      }
                      else if(strncmp(R->method, "GET", 3) == 0) {
                          handle_get(R, req, i);
													int q  = sizeof(req);
													req[q] = '\0';
													printf("GET REQUEST: %s\n\n", req);
                      }
                      else {
                          perror("Invalid HTTP Method for Proxy!");
                      }
											if (R)
                      	free_r(R);
                      sor = j + 3;
                  }
              }
							free(bigBuf);
            }
        }
      }
    }
}
	close(master_socket);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(serv_ctx);
  destroyTunnels();

  return 0;
}
