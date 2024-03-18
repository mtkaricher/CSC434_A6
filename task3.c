#include <stdio.h>
#include <openssl/bn.h>

//function to print big number
void printBN(char *msg, BIGNUM *a) {
        //convert the BN type to number string then print
        char * number_str = BN_bn2hex(a);
        printf("%s %s\n", msg, number_str);
        //finish by freeing the DAM
        OPENSSL_free(number_str);
}

int main() {

	//declare all big numeber variables
	BN_CTX *ctx = BN_CTX_new(); //context to store and variables during extended ops
	BIGNUM *n = BN_new(); //product of p and q
	BIGNUM *d = BN_new(); //private key
	BIGNUM *cipHex = BN_new(); //ciphertext hex
	BIGNUM *mesHex = BN_new(); //variable to store hex of decrypted text

	//Initialize variables with given documentation
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&cipHex, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	
	//decrypt message with formula from class mesHex = cipHex^d mod n
	BN_mod_exp(mesHex, cipHex, d, n, ctx);

	//now that we have the plaintext stored in mesHex, we will print it using the above function
	printBN("", mesHex);

	return 0;
}
