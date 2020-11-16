EXECUTABLES = proxy parse_tests

INCLUDES = parse.h

# Do all C compies with gcc (at home you could try clang)
CC = gcc

# Updating include path to use current directory
IFLAGS = -I.

# the next three lines enable you to compile and link against course software
PREFLAGS = -g -Wall $(IFLAGS)
POSTFLAGS = -lnsl

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
