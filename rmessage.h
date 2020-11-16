#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct RMessage {
  int client_sfd;
  char *request;
  struct RMessage *next;
} RMessage;

void push_rmessage_empty(RMessage *head, RMessage *r);

void push_rmessage_back(RMessage *head, RMessage *r);

RMessage *find_rmessage_sfd(RMessage *head, int s);

void free_rmessage(RMessage *head, RMessage *r);
