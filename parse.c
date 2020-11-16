#include "parse.h"


void clean(char *l) {
  int len = strlen(l);
  while ( l[len-1] == '\n' || l[len-1] == '\r' )
    l[--len] = '\0';
}

void free_all(char *a, char *b, char *c, char *d, Request *r) {
  free(a);
  free(b);
  free(c);
  free(d);
  free(r);
}

void free_r(Request *r) {
  free(r->method);
  free(r->url);
  free(r->host);
  free(r);
}

// Takes a null-terminated char *.
// Returns NULL if request could not be parsed
// Returns struct * Request with parsed information otherwise
Request *parse_request(char *header) {
  char *temp_header, *line, *url, *host, *method;
  Request *r;
  int port;
  int len = strlen(header);

  r = malloc(sizeof(Request));
  temp_header = malloc(len+1);
  url = malloc(len);
  host = malloc(len);
  method = malloc(100);
  if(!temp_header || !url || !host || !method || !r)
    printf("Error with malloc\n");

  memset(temp_header, 0, len+1);
  strcpy(temp_header, header);
  line = strtok(temp_header, "\n");
  clean(line);

  if (sscanf(line, "%[^ ] %[^ ] %*[^ ]", method, url) != 2) {
    free_all(temp_header, url, host, method, r);
    return NULL;
  }

  // Absolute form URI required for HTTP requests to a proxy (RFC 2616 5.1.2)
  // URI form must be hostname:portno for CONNECT requests (RFC 7231 4.3.6)
  if ((strcmp(method, "GET") == 0) || strncmp(url, "http://", 7) == 0) {
    if (sscanf(url, "http://%[^:]:%d%*[^ ]", host, &port) == 2)
      port = port;
    else if (sscanf(url, "http://%[^/]%*[^ ]", host) == 1)
      port = 80;
    else {
      free_all(temp_header, url, host, method, r);
      return NULL;
    }
  }
  else if (strcmp(method, "CONNECT") == 0) {
    if (sscanf(url, "%[^:]:%d", host, &port) == 2)
      port = port;
    else {
      free_all(temp_header, url, host, method, r);
      return NULL;
    }
  }
  else {
    free_all(temp_header, url, host, method, r);
    return NULL;
  }

  r->url = url;
  r->method = method;
  r->port = port;
  r->host = host;
  free(temp_header);
  return r;
}
