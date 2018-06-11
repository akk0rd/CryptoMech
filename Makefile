all:
	g++ -DNDEBUG -g3 -O2 -Wall -Wextra -o crRab cryptoRabin.cpp -l:libcryptopp.a
clean:
	rm -rf crRab
