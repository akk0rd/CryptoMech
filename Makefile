GCC	= gcc -Wall
SOURCE	= barrett.c
OBJECT	= barrett
DEPENDS = bignum.c
FLAGS = OPTIMIZE
DEBUG = -g

all:
	$(GCC) $(SOURCE) $(DEPENDS) -o $(OBJECT) $(DEBUG)
clean:
	rm -rf $(OBJECT)
