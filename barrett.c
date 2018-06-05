#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "bignum.h"

int log2_4_int( const mbedtls_mpi* N )  
{    
    mbedtls_mpi n;
    mbedtls_mpi_init( &n );
    mbedtls_mpi_copy(&n, N);
    unsigned int ans = 0 ;
    while( *n.p ) {
        ans++;
        mbedtls_mpi_shift_r( &n, 1 );
    }
    return ans - 1 ;  
} 

int Pow(mbedtls_mpi* R, const mbedtls_mpi* X, const mbedtls_mpi* N)
{
    mbedtls_mpi A, B;
    mbedtls_mpi_init( &A );
    mbedtls_mpi_init( &B );
    mbedtls_mpi_read_string( &B, 10, "1" );
    mbedtls_mpi_copy(&A, N);

    do{
        mbedtls_mpi_sub_int( &A, &A, 1);
        mbedtls_mpi_mul_mpi( &B, &B, X);
    }while( *A.p );
    mbedtls_mpi_copy(R, &B);
    return 0;
}

int barrett(mbedtls_mpi* R, const mbedtls_mpi* X, const mbedtls_mpi* N)
{
    char buff[512];
    mbedtls_mpi A, B, C, r, T;
    mbedtls_mpi_init( &A );
    mbedtls_mpi_init( &B );
    mbedtls_mpi_init( &C );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &T );

    int k = log2_4_int( N );
    mbedtls_mpi_read_string( &A, 10, "4" );
    sprintf(buff, "%d", k);
    mbedtls_mpi_read_string( &B, 10, buff );
    Pow(&C, &A, &B);
    mbedtls_mpi_div_mpi(&r, NULL, &C, N);
    mbedtls_mpi_mul_mpi(&A, X, &r);
    mbedtls_mpi_div_mpi(&r, NULL, &A, &C);
    mbedtls_mpi_mul_mpi(&B, &r, N);
    mbedtls_mpi_sub_mpi(&T, X, &B);
    if(mbedtls_mpi_cmp_mpi(&T,N) == -1)
        mbedtls_mpi_copy(R, &T);
    else if(mbedtls_mpi_cmp_mpi(&T,N) == 1)
        mbedtls_mpi_sub_mpi(R, &T, N);
    return 0;
}

int main()
{
    char x[512], n[512];
    mbedtls_mpi A, B, C;
    mbedtls_mpi_init( &A );
    mbedtls_mpi_init( &B );
    mbedtls_mpi_init( &C );

    printf("input number: ");
    scanf("%s", x);
    printf("input modulus: ");
    scanf("%s", n);
    mbedtls_mpi_read_string( &A, 10, x );
    mbedtls_mpi_read_string( &B, 10, n );

    barrett(&C, &A, &B);
    printf("result: ");
    mbedtls_mpi_write_file(NULL, &C, 10, NULL );
    return 0;
}