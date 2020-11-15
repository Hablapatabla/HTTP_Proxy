#include "proxy.h"

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


// Invalid Request - CONNECT
void test5() {
  char *header = "CONNECT http://www.test.org/simple-path HTTP/1.1\r\nHost: www.test.org/simple-path\r\n\r\n";
  Request *r = parse_request(header);
  if (r == NULL)
    printf("test 5 - Invalid - CONNECT FAILED, did not reject invalid request, protocol should not be in URL\n");
  else {
    printf("test 5 - Invalid - CONNECT PASSED\n");
    free_r(r);
  }

}


// Invalid Request - GET
void test4() {
  char *header = "GET http://www.test.org/simple-pathHTTP/1.1\r\nHost: www.test.org/simple-path\r\nContent-Type: text/plain\r\n\r\n";
  Request *r = parse_request(header);
  if (r == NULL)
    printf("test 4 - Invalid - GET FAILED, did not reject invalid request\n");
  else {
    printf("test 4 - Invalid - GET PASSED\n");
    free_r(r);
  }
}


// Valid Request - CONNECT - NonStandard Port
void test3() {
  char *header = "CONNECT example.test.com:92 HTTP/1.1\r\nHost: example.test.com:92\r\nProxy-Authorization: basic aGVsbG86d29ybGQ=\r\n\r\n";
  Request *r = parse_request(header);
  if (r == NULL)
    printf("test 3 - Valid - Connect - Nonstandard port FAILED, could not parse\n");
  else {
    if(strcmp(r->url, "example.test.com:92") != 0 ||
       strcmp(r->host, "example.test.com") != 0 ||
       strcmp(r->method, "CONNECT") != 0 ||
       r->port != 92) {
         printf("test 3- Valid - CONNECT - Nonstandard port FAILED, incorrect parsing.\n URL: %s\n Host: %s\n Method: %s\n Port: %d\n",
                r->url, r->host, r->method, r->port);
       }
    else {
      printf("test 3- Valid - CONNECT - nonstandard port PASSED\n");
    }
    free_r(r);
  }
}

// Valid Request - CONNECT - Standard Port
void test2() {
  char *header = "CONNECT comet.my.test.com:80 HTTP/1.1\r\nHost: comet.my.test.com:80\r\nProxy-Authorization: basic aGVsbG86d29ybGQ=\r\n\r\n";
  Request *r = parse_request(header);
  if (r == NULL)
    printf("test 2 - Valid - Connect FAILED, could not parse\n");
  else {
    if(strcmp(r->url, "comet.my.test.com:80") != 0 ||
       strcmp(r->host, "comet.my.test.com") != 0 ||
       strcmp(r->method, "CONNECT") != 0 ||
       r->port != 80) {
         printf("test 2 - Valid - CONNECT FAILED, incorrect parsing.\n URL: %s\n Host: %s\n Method: %s\n Port: %d\n",
                r->url, r->host, r->method, r->port);
       }
    else {
      printf("test 2- Valid - CONNECT PASSED\n");
    }
    free_r(r);
  }
}


// Valid Request - GET - standard port- NON HTTPS
void test1() {
  char *header = "GET http://www.test.org/simple-path HTTP/1.1\r\nHost: www.test.org\r\nContent-Type: text/plain\r\n\r\n";
  Request *r = parse_request(header);
  if (r == NULL)
    printf("test 1 - Valid - GET - NON HTTPS FAILED, could not parse\n");
  else {
    if(strcmp(r->url, "http://www.test.org/simple-path") != 0 ||
       strcmp(r->host, "www.test.org") != 0 ||
       strcmp(r->method, "GET") != 0 ||
       r->port != 80) {
         printf("test 1 - Valid - GET - NON HTTPS FAILED, incorrect parsing.\n URL: %s\n Host: %s\n Method: %s\n Port: %d\n",
                r->url, r->host, r->method, r->port);
       }
    else {
      printf("test 1 - Valid - GET - NON HTTPS PASSED\n");
    }
    free_r(r);
  }
}

int main(int argc, char *argv[]) {
  printf("Here we go baby\n");
  test1();
  test2();
  test3();
  test4();
  test5();
  return 0;
}
