#include <iostream>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/rabin.h>
#include <cryptopp/filters.h>
 
using namespace CryptoPP;
using namespace std;
 
int main(){
AutoSeededRandomPool prng;

Rabin::PrivateKey privKey;
privKey.GenerateRandomWithKeySize(prng, 128);
Rabin::PublicKey pubKey(privKey);

string message, recovered;
Integer m, c, r;

message = "secret";
cout << "message: " << message << endl;

// Treat the message as a big endian array
m = Integer((const byte *)message.data(), message.size());
cout << "m: " << hex << m << endl;

// Encrypt
c = pubKey.ApplyFunction(m);
cout << "c: " << hex << c << endl;

// Decrypt
r = privKey.CalculateInverse(prng, c);
cout << "r: " << hex << r << endl;

// Round trip it
size_t req = r.MinEncodedSize();
recovered.resize(req);
r.Encode((byte *) &recovered[0], recovered.size());

cout << "recovered: " << recovered << endl;	
}

