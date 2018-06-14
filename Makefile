all:
	g++ -DNDEBUG -g3 -O2 -Wall -Wextra -o crRab cryptoRabin.cpp -l:libcryptopp.a
	gcc rabin.c bignum.c -o rabin -ggdb
clean:
	rm -rf crRab