#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

//First, I need to create the method to print any big numbers
void printBN(char *msg, BIGNUM *a) {
	//convert the BN type to number string then print
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	//finish by freeing the DAM
	OPENSSL_free(number_str);
}

int main() {
	//for main, I will be implementing the secret key formula
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *p = BN_new(); //p
	BIGNUM *q = BN_new(); //q
	BIGNUM *e = BN_new(); //e
	BIGNUM *d = BN_new(); //secret key
	BIGNUM *n = BN_new(); //n
	BIGNUM *pon = BN_new(); //pi of n (p-1)*(q-1)
	BIGNUM *one = BN_new(); //create a 1 to use in bn operations
	BIGNUM *pmo = BN_new(); //p minus one
	BIGNUM *qmo = BN_new(); //q minus one

	//now, initialize the given variables
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	BN_dec2bn(&one, "1");

	//create pi of n for use in later mod operation
	//I will have to create extra variables to store p-1 and q-1
	BN_sub(pmo, p, one);
	BN_sub(qmo, q, one);

	//create pi of n
	BN_mul(pon, pmo, qmo, ctx);

	//perform mod operation, d = e^(-1) mod pon
	BN_mod_inverse(d, e, pon, ctx);

	//call the function created at the top to print the private key
	printBN("",d);
		
	return 0;
}
