#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bignum.h"

#define SIZE    512

size_t log2_4_int( size_t n )  
{    
  unsigned int ans = 0 ;
  while( n>>=1 ) ans++;
  return ans ;  
}  

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
}

int pick_key(mbedtls_mpi* P, mbedtls_mpi* Q, mbedtls_mpi* N)
{
    assert((P && Q && N) && "bad arguments");
    mbedtls_mpi_read_string( &N, 10, "1");

    mbedtls_mpi_uint res = 1;
    while ( res != 3) 
    {
        mbedtls_mpi_gen_prime(&P, SIZE, 0, myrand, NULL);
        mbedtls_mpi_mod_int(&res, &P, 8);
    }
    res = 1;
    while ( res != 7) 
    {
        mbedtls_mpi_gen_prime(&Q, SIZE, 0, myrand, NULL);
        mbedtls_mpi_mod_int(&res, &Q, 8);
    }
    mbedtls_mpi_mul_mpi(&N, &P, &Q);
}

int main()
{
    return 0;
}