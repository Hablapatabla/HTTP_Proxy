#Makefile for project
CC = gcc
PREFLAGS = -g -Wall
POSTFLAGS = -lnsl

default: proxy

all: proxy parse_tests

proxy: proxy.o
	$(CC) $(PREFLAGS) -o proxy proxy.o $(POSTFLAGS)

proxy.o: proxy.c
	$(CC) $(PREFLAGS) -c proxy.c $(POSTFLAGS)

parse_tests: parse_tests.o
	$(CC) $(PREFLAGS) -o parse_tests parse_tests.o $(POSTFLAGS)

parse_tests.o: parse_tests.c
	$(CC) $(PREFLAGS) -c parse_tests.c $(POSTFLAGS)

clean:
	$(RM) proxy parse_tests *.o *~
