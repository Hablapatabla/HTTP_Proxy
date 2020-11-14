#Makefile for project
CC = gcc
PREFLAGS = -g -Wall
POSTFLAGS = -lnsl

default: proxy

all: proxy

proxy: proxy.o
	$(CC) $(PREFLAGS) -o proxy proxy.o $(POSTFLAGS)

proxy.o: proxy.c
	$(CC) $(PREFLAGS) -c proxy.c $(POSTFLAGS)

clean:
	$(RM) proxy *.o *~
