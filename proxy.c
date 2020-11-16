#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>

#include "parse.h"
#include "rmessage.h"

RMessage *rms_head = NULL;


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
  int master_socket, client_socket, client_size, message_size, rv;
  socklen_t client_len;
  char remoteIP[INET6_ADDRSTRLEN];
  int yes = 1;
  int portno = 0;
  struct sockaddr_storage client_addr;

  if(argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }
  portno = atoi(argv[1]);

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

  fd_set master_set, temp_set;

  FD_ZERO(&master_set);
  FD_ZERO(&temp_set);
  FD_SET(master_socket, &master_set);

  int fdmax = master_socket;

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
          client_size = sizeof(client_addr);
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

        }
      }
    }



  }



  printf("Here we go baby\n");
  clean("hi");
  return 0;
}
