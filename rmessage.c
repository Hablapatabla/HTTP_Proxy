#include "rmessage.h"

void push_rmessage_empty(RMessage *head, RMessage *r) {
  r->next = NULL;
  head = r;
}

void push_rmessage_back(RMessage *head, RMessage *r) {
  if(!head) {
    push_rmessage_empty(head, r);
    return;
  }

  RMessage *last = head;
  while(last->next)
    last = last->next;
  last->next = r;
}

RMessage *find_rmessage_sfd(RMessage *head, int s) {
  if(!head)
    return NULL;
  RMessage *temp = head;
  if(!temp->next && temp->client_sfd != s)
    return NULL;

  while(temp && temp->client_sfd != s)
    temp = temp->next;

  return temp;
}

void free_rmessage(RMessage *head, RMessage *r) {
  if(!r)
    return;
  int sockfd = r->client_sfd;
  RMessage *before = head;
  RMessage *current = head;

  if(current && current->client_sfd == sockfd) {
    head = current->next;
    free(current);
    return;
  }
  while(current && current->client_sfd != sockfd) {
    before = current;
    current = current->next;
  }

  if(!current)
    return;
  before->next = current->next;
  free(current);
}
