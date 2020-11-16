#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct Request {
  char *url;
  char *host;
  char *method;
  int port;
} Request;

void clean(char *l);

void free_all(char *a, char *b, char *c, char *d, Request *r);

void free_r(Request *r);

// Takes a null-terminated char *.
// Returns NULL if request could not be parsed
// Returns struct * Request with parsed information otherwise
Request *parse_request(char *header);
