GCC	= gcc -Wall
SOURCE	= bbs.c
OBJECT	= bbs
DEPENDS = bignum.c
FLAGS = OPTIMIZE
DEBUG = -g

fast:
	$(GCC) $(SOURCE) $(DEPENDS) -o $(OBJECT) -D $(FLAGS)
slow:
	$(GCC) $(SOURCE) $(DEPENDS) -o $(OBJECT)  
clean:
	rm -rf $(OBJECT)
