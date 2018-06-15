for generated DER certificate and encrypted message 
use ./rabin with unix commands:
  > echo "secret"|xxd -p|./rabin
save it to config file:
  > echo "secret"|xxd -p|./rabin > ans1struct
and generate DER cert:
  > openssl asn1parse -genconf asn1struct -out rabin_key.dat
set encrypted message to cryptoRabin.cpp build and run ./crRab
