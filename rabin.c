#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "bignum.h"

#define SIZE    512
#define SIZE_M   64

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
    mbedtls_mpi pm1, qm1, tmp, r;
    mbedtls_mpi_init(&pm1);
    mbedtls_mpi_init(&qm1);
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&r);

    mbedtls_mpi_sub_int(&pm1, P, 1);        // p-1
    mbedtls_mpi_sub_int(&qm1, Q, 1);        // q-1
    mbedtls_mpi_mul_mpi(&r, &pm1, &qm1);    // (p-1)(q-1)
    mbedtls_mpi_div_int(&tmp, NULL, &r, 4);     // 1/4(p-1)(q-1)
    mbedtls_mpi_free(&r);
    mbedtls_mpi_add_int(&r, &tmp, 1);       // 1/4 (p-1)(q-1) + 1
    mbedtls_mpi_div_int(R, NULL, &r, 2);       // 1/2 (1/4 (p-1)(q-1) + 1)

}

int encoding(mbedtls_mpi* C, mbedtls_mpi* c2, const mbedtls_mpi* S, 
    const mbedtls_mpi* C1, const mbedtls_mpi* M, const mbedtls_mpi* N)
{
     mbedtls_mpi a, b, n, s, ms, r, tmp;

    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&ms);

    mbedtls_mpi_exp_mod(&a, S, C1, N, NULL);    // S^c1 mod N
    mbedtls_mpi_mul_mpi(&b, &a, M);             // M*S^c1
    mbedtls_mpi_mod_mpi(&ms, &b, N);            // M*S^c1 mod N

    mbedtls_mpi_read_string(&a , 10, "2");
    mbedtls_mpi_exp_mod(C, &ms, &a, N, NULL);   // C = M`^ 2 mon N
    mbedtls_mpi_mod_mpi(c2, &ms, &a);           // c2 = M` mod 2
}
int decoding(mbedtls_mpi* M, const mbedtls_mpi* K, const mbedtls_mpi* C,
    const int* C1, const mbedtls_mpi* C2, const mbedtls_mpi* N)
    {
    mbedtls_mpi tmp, sc, d, r;

    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&sc);
    mbedtls_mpi_init(&r);

    mbedtls_mpi_exp_mod(&d, C, K, N, NULL);     //C^k mod N
    /*
     * M = (D_1/4-1)/2 if D_1=0pmod{4}
     * M = ((N-D_1)/4-1)/2 if D_1=1pmod{4}
     * M = (D_1/2-1)/2 if D_1=2pmod{4}
     * M = ((N-D_1/2-1)/2 if D_1=3pmod{4}
    **/
    int res;
    mbedtls_mpi_mod_int(&res, &d, 4);
    switch(res){
        case(0):
            mbedtls_mpi_div_int(&tmp, NULL, &d, 4);
            mbedtls_mpi_sub_int(&r, &tmp, 1);
            mbedtls_mpi_div_int(M, NULL, &r, 2);
            break;
        case(1):
            mbedtls_mpi_sub_mpi(&r, N, &d);
            mbedtls_mpi_div_int(&tmp, NULL, &r, 4);
            mbedtls_mpi_sub_int(&r, &tmp, 1);
            mbedtls_mpi_div_int(M, NULL, &r, 2);
            break;
        case(2):
            mbedtls_mpi_div_int(&tmp, NULL, &d, 2);
            mbedtls_mpi_sub_int(&r, &tmp, 1);
            mbedtls_mpi_div_int(M, NULL, &r, 2);
            break;
        case(3):
            mbedtls_mpi_sub_mpi(&r, N, &d);
            mbedtls_mpi_div_int(&tmp, NULL, &r, 2);
            mbedtls_mpi_sub_int(&r, &tmp, 1);
            mbedtls_mpi_div_int(M, NULL, &r, 2);
            break;
    }
    }

int main()
{
    mbedtls_mpi p, q, n, s, m, k, tmp, c, c2, op;

    mbedtls_mpi_init(&n);
    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&q);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&m);
    mbedtls_mpi_init(&c);
    mbedtls_mpi_init(&c2);
    mbedtls_mpi_init(&op);
    mbedtls_mpi_init(&tmp);

    pick_key(&p,&q,&n);
    //mbedtls_mpi_read_string(&p,10,"7");
    //mbedtls_mpi_read_string(&q,10,"13");
    //mbedtls_mpi_read_string(&n,10,"91");

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
    calculate_k(&k, &p, &q);
    sprintf(msg, "%d", c1);
    mbedtls_mpi_read_string(&tmp,10,msg);
    encoding(&c, &c2, &s, &tmp, &m, &n);
    decoding(&op, &k, &c, &c1, &c2, &n);
    printf("Encoding message:  ");
    mbedtls_mpi_write_file(NULL, &op, 16, NULL );
    printf("C1: %i\n", c1);
    printf("C2: ");
    mbedtls_mpi_write_file(NULL, &c2, 16, NULL );
    

    return 0;
}