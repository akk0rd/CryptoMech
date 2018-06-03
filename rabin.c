#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bignum.h"

#define SIZE    512
#define SIZE_M    128

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
    mbedtls_mpi_read_string( N, 10, "1");

    mbedtls_mpi_uint res = 1;
    while ( res != 3) 
    {
        mbedtls_mpi_gen_prime(P, SIZE, 0, myrand, NULL);
        mbedtls_mpi_mod_int(&res, P, 8);
    }
    while ( res != 7) 
    {
        mbedtls_mpi_gen_prime(Q, SIZE, 0, myrand, NULL);
        mbedtls_mpi_mod_int(&res, Q, 8);
    }
    mbedtls_mpi_mul_mpi(N, P, Q);
}

int jacobi(const mbedtls_mpi* A, const mbedtls_mpi* N) {
    int ans;
    mbedtls_mpi_uint res = 1;


    if (mbedtls_mpi_cmp_int_(A,0))
        ans = mbedtls_mpi_cmp_int_(N, 1) ? 1 : 0;
    else if (mbedtls_mpi_cmp_int_(A,2)) {
        mbedtls_mpi_mod_int(&res, N, 8);
        switch ( res ) {
            case 1:
            case 7:
                    ans = 1;
                    break;
            case 3:
            case 5:
                    ans = -1;
                    break;
        }
    }
    else if ( (res = mbedtls_mpi_cmp_mpi(A,N)) == 1 || res == 0 )
    {
        mbedtls_mpi tmp;
        mbedtls_mpi_init(&tmp);
        mbedtls_mpi_mod_mpi(&tmp, A, N);
        ans = jacobi(&tmp, N);
    }
    else if ( mbedtls_mpi_mod_int(&res, A, 2) && res == 0 )
    {
        mbedtls_mpi tmp, int2;
        mbedtls_mpi_init(&tmp);
        mbedtls_mpi_init(&int2);
        mbedtls_mpi_read_string( &int2, 10, "2");
        mbedtls_mpi_div_int(&tmp, NULL, A, 2);
        ans = jacobi(&int2, N)*jacobi(&tmp, N);
    }
    else{
        int cong_a,cong_n;
        mbedtls_mpi_mod_int(&cong_a, A, 4);
        mbedtls_mpi_mod_int(&cong_n, N, 4);
        ans = ( cong_a == 3 && cong_n == 3 ) ? -jacobi(N,A) : jacobi(N,A);
    }
    return ans;
}
//k = 1/2 (1/4 (p - 1) (q - 1) + 1)
int calculate_k(mbedtls_mpi* R, const mbedtls_mpi* P, const mbedtls_mpi* Q)
{
    mbedtls_mpi pm1, qm1, n, x1, r, x0, tmp;
    mbedtls_mpi_init(&pm1);
    mbedtls_mpi_init(&qm1);
    mbedtls_mpi_init(&tmp);

    mbedtls_mpi_sub_int(&pm1, P, 1);        // p-1
    mbedtls_mpi_sub_int(&qm1, Q, 1);        // q-1
    mbedtls_mpi_mul_mpi(&r, &pm1, &qm1);    // (p-1)(q-1)
    mbedtls_mpi_mul_int(&tmp, &r, 1/4);     // 1/4(p-1)(q-1)
    mbedtls_mpi_sub_mpi(&r, &tmp, 1);       // 1/4 (p-1)(q-1) + 1
    mbedtls_mpi_mul_int(&tmp, &r, 1/2);     // 1/2 (1/4 (p-1)(q-1) + 1)

}


int main()
{
    mbedtls_mpi p, q, n, s, m, r, tmp;

    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&m);
    mbedtls_mpi_init(&tmp);

    pick_key(&p,&q,&n);

    do{
        mbedtls_mpi_fill_random(&s, SIZE_M, myrand, NULL);
    }while(jacobi(&s,&n) != -1);

    char msg[2048];
    scanf("%s", msg);
    mbedtls_mpi_read_string(&m,16,msg);

    int c1;
    switch(jacobi(&m,&n)){
        case(1):
            c1 = 0;
            break;
        case(-1):
            c1 = 1;
            break;
    }


    mbedtls_mpi_write_file(NULL, &m, 10, NULL );

    return 0;
}
/*
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

    pick_key(&p, &q, &n);

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
*/