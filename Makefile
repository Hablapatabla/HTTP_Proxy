EXECUTABLES = proxy parse_tests

INCLUDES = parse.h partial.h

# Do all C compies with gcc (at home you could try clang)
CC = gcc

# Updating include path to use current directory
IFLAGS = -I.

LFLAGS = -L/usr/local/lib

PREFLAGS = -Wall $(IFLAGS) $(LFLAGS)
POSTFLAGS = -g3 -lssl -lcrypto

default: proxy

all: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES) *.o

%.o:%.c $(INCLUDES)
	$(CC) $(PREFLAGS) -c $<

#
# Individual executables
#
#    Each executable depends on one or more .o files.
#    Those .o files are linked together to build the corresponding
#    executable.
#
proxy: proxy.o parse.o
	$(CC) $(PREFLAGS) -o proxy proxy.o parse.o $(POSTFLAGS)

parse_tests: parse_tests.o parse.o
	$(CC) $(PREFLAGS) -o parse_tests parse_tests.o parse.o $(POSTFLAGS)
