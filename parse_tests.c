#include "parse.h"

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
       strcmp(r->path, "/simple-path") !=0 ||
       r->port != 80) {
         printf("test 1 - Valid - GET - NON HTTPS FAILED, incorrect parsing.\n URL: %s\n Host: %s\n Method: %s\n Path: %s\nPort: %d\n",
                r->url, r->host, r->method, r->path, r->port);
       }
    else {
      printf("test 1 - Valid - GET - NON HTTPS PASSED\n");
    }
    free_r(r);
  }
}

int main(int argc, char *argv[]) {
  printf("Here we go baby\n");
  char *test = "GET www.google.com HTTP/1.1\r\nContent-len: 15\r\n\r\n";
  char *line = malloc(100);
  if (sscanf(test, "%[^\r\n\r\n]\r\n\r\n", line) == 1)
    printf("%s\n", line);
  test1();
  test2();
  test3();
  test4();
  test5();
  return 0;
}
