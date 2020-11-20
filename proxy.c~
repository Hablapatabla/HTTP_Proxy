#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "parse.h"
#include "rmessage.h"

#define BUFSIZE 8192
#define CACHESIZE 30
#define ONEHOUR 3600
#define STARTOFCACHEFIELD "Cache-Control: "
#define STARTOFCACHE " "
#define ENDOFCACHE " "


typedef struct CacheElement {
	char *data, *url;
	int max_age, port;
	time_t entry_time, last_retrieval_time;
} CacheElement;

struct connTunnel {
    int clientfd;
    int serverfd;
    struct connTunnel *next;
};

struct connTunnel *root = NULL;

void addTunnel_H(int cfd, int sfd, struct connTunnel *t) {
    if(t == NULL) {
        t = (struct connTunnel*) malloc(sizeof(struct connTunnel));
        t->clientfd = cfd;
        t->serverfd = sfd;
        t->next = NULL;
    }
    else {
        addTunnel_H(cfd, sfd, t->next);
    }
}

void addTunnel(int cfd, int sfd) {
    addTunnel_H(cfd, sfd, root);
}

void remTunnel_H(int cfd, int sfd, struct connTunnel *t, 
                                  struct connTunnel *prev) {
    if(t == NULL) {
        return;
    }
    else if(t->clientfd == cfd || t->serverfd == sfd) {
        if(prev != NULL) {
            prev->next = t->next;
            free(t);
            t = NULL;
        }
        else {
            struct connTunnel *temp = t->next;
            free(t);
            t = temp;
        }
    }
    else {
        remTunnel_H(cfd, sfd, t->next, t);
    }
}

void remTunnel(int cfd, int sfd) {
    remTunnel_H(cfd, sfd, root, NULL);
}

int findPartner_H(int fd, struct connTunnel *t){
    if(t == NULL){
        return -1;
    }
    else if(t->clientfd == fd){
        return t->serverfd;
    }
    else if(t->serverfd == fd){
        return t->clientfd;
    }
    else {
        return findPartner_H(fd, t->next);
    }
}

int findPartner(int fd) {
    return findPartner_H(fd, root);
}

void destroyTunnels_H(struct connTunnel *t) {
    if(t != NULL) {
        destroyTunnels_H(t->next);
        close(t->clientfd);
        close(t->serverfd);
        free(t);
    }
}

void destroyTunnels() {
    destroyTunnels_H(root);
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
    printf("Url: %s\n", url);
    printf("Cache url: %s\n", cache[index].url);
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
	if(cache[0].last_retrieval_time) {
		time_t oldest = cache[0].last_retrieval_time;
		int oldest_index = 0;
		double difference;
		for(int i = 1; i < CACHESIZE; ++i) {
			if(cache[i].last_retrieval_time) {
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
void refresh_element(CacheElement **c, int index, char *response, int port)
{
  int age = parse_age(response);
  time_t curr_time = time(NULL);
  (*c)[index].entry_time = curr_time;
  (*c)[index].max_age = age;
  (*c)[index].last_retrieval_time = NULL;
  (*c)[index].data = response;
  (*c)[index].port = port;
}


char *get_response(Request *r, char *request) {
  int sockfd, message_size, total, new_buf_size;
  struct sockaddr_in server_addr;
  struct hostent *server;
  char *buffer;
  buffer = calloc(BUFSIZE, sizeof(char));
  if(!buffer)
    error("Error callocing buffer (get_response)\n");

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
  printf("wrote????\n");
  message_size = read(sockfd, buffer, BUFSIZE - 1);
  if(message_size < 0)
    error("Error reading packet (handle_request)\n");

  char temp[BUFSIZE];
  bzero(temp, BUFSIZE);
  new_buf_size = 2 * BUFSIZE;
  while((message_size = read(sockfd, temp, BUFSIZE - 1)) != 0) {
    if(message_size < 0)
      error("Error reading rest of packet (handle_request)\n");
    buffer = realloc(buffer, new_buf_size);
    if(!buffer)
      error("Failed to realloc buffer (handle_request)\n");
    strcat(buffer, temp);
    new_buf_size += BUFSIZE;
    bzero(temp, BUFSIZE);
  }
  close(sockfd);
  return buffer;
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
  printf("One of these? Url: %s\n", r->url);
  printf("port: %d\n", r->port);
  int index = is_cached(r->url, cache, num_cached, r->port);
  if (index == -1) {
    printf("Should be in here\n");
    char *server_response = get_response(r, request);
    time_t creation_time = time(NULL);
    int age = parse_age(server_response);
    CacheElement e = { .max_age = age, .entry_time = creation_time,
      .last_retrieval_time = NULL, .data = server_response,
      .url = strdup(r->url), .port = r->port};
    cache_insert(&cache, &e, &num_cached);
    if((message_size = write(client_sfd, server_response,
                                strlen(server_response))) < 0)
        error("Error writing to socket\n");
  }
  else {
    time_t curr_time = time(NULL);
    if (difftime(curr_time, cache[index].entry_time)< cache[index].max_age) {
      printf("Sending from cache\n");
      update_retrieved(&cache, index);
      if((message_size = write(client_sfd, cache[index].data,
                                            strlen(cache[index].data))) < 0)
          error("Error writing to socket\n");
    }
    else {
      printf("not cached\n");

      char *server_response = get_response(r, request);
      refresh_element(&cache, index, server_response, r->port);
      if((message_size = write(client_sfd, server_response,
                                  strlen(server_response))) < 0)
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
  return sockfd;
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
FD_ZERO(&server_set);
FD_ZERO(&client_set);
FD_SET(master_socket, &master_set);

int fdmax = master_socket;
int nbytes;

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
            if ((nbytes = recv(i, buf, sizeof buf, 0)) <= 0) {
                if(nbytes == 0) {
                    //Connection closed
                    printf("selectserver: socket %d hung up\n", i);
                }
                else {
                    perror("recv");
                }
                close(i);
                FD_CLR(i, &master_set);
                int partner;
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
                    if(send(partner, bigBuf, totalSize, 0) == -1) {
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
                            if(strcmp(R->method, "CONNECT") == 0) {
                                int newServ = handle_connect(R, req, i);
                                FD_SET(i, &server_set);
                                addTunnel(i, newServ);
                            }
                            else if(strcmp(R->method, "GET")) {
                                handle_get(R, req, i);
                            }
                            else {
                                perror("Invalid HTTP Method for Proxy!");
                            }
                            free_r(R);
                            sor = j + 3;
                        }
                    }
                }
                free(bigBuf);
            }
        }
      }
    }
}
  destroyTunnels();
  return 0;
}
