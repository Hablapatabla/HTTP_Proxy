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


#define BUFSIZE 1000

RMessage *rms_head = NULL;

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
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
}

return &(((struct sockaddr_in6*)sa)->sin6_addr);
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
                char * bigBuf = (char *) calloc(1000, sizeof(char));
                int totalSize = nbytes;
                memcpy(bigBuf, buf, nbytes);
                while(nbytes == 1000) {
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
                            char req[1001] = { 0 };
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
