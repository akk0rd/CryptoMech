GCC	= gcc -Wall
SOURCE	= rabin.c
OBJECT	= rabin
DEPENDS = bignum.c
FLAGS = OPTIMIZE
DEBUG = -g

all:
	$(GCC) $(SOURCE) $(DEPENDS) -o $(OBJECT) $(DEBUG)
clean:
	rm -rf $(OBJECT)
