#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main()
{
    mbedtls_mpi p, q, n, x1, r, x0, tmp;
    unsigned char val;
    int bit;

    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&x0);
    mbedtls_mpi_init(&x1);
    mbedtls_mpi_init(&tmp);

    mbedtls_mpi_read_string( &n, 10, "1");

    mbedtls_mpi_gen_prime(&p, SIZE, 0, myrand, NULL);

    mbedtls_mpi_uint res = 1;
    while ( res != 3) 
    {
        mbedtls_mpi_gen_prime(&q, SIZE, 0, myrand, NULL);
        mbedtls_mpi_mul_mpi(&n, &p, &q);
        mbedtls_mpi_mod_int(&res, &n, 4);
    }
    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&q);

    mbedtls_mpi_read_string( &r, 10, "0");
    while (!mbedtls_mpi_cmp_int_(&r, 1)) {
        mbedtls_mpi_fill_random(&x1, SIZE, myrand, NULL);
        mbedtls_mpi_gcd(&r, &n, &x1);
    }
    mbedtls_mpi_free(&r);

    mbedtls_mpi_mul_mpi(&tmp, &x1, &x1);
    mbedtls_mpi_mod_mpi(&x0, &tmp, &n);

    bit  = 0;

    for ( ; ; ) {
        mbedtls_mpi_mul_mpi(&tmp, &x0, &x0);
        mbedtls_mpi_mod_mpi(&x1, &tmp, &n);
#ifdef OPTIMIZE
        size_t j;
        for(j = 0; j < log2_4_int(mbedtls_mpi_bitlen(&x1)); j++){
#endif
        if (bit == 0) {
            val = 0;
        }
#ifndef OPTIMIZE
        if ( mbedtls_mpi_get_bit(&x1, 0)) {
#else
        if ( mbedtls_mpi_get_bit(&x1, j)) {
#endif        
            val |= (1 << bit);
        }

        bit++;
        if (bit == 8) {
            //(void)printf ("%02x", val);
            (void)printf ("%03i", val);
            bit = 0;
        }
#ifdef OPTIMIZE      
        }
#endif

        mbedtls_mpi_copy(&x0, &x1);
    }

    fflush(stdout);
    return(0);
}