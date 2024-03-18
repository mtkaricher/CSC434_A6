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

	//declare variables e, n, d, original message, cipher text
	BN_CTX *ctx = BN_CTX_new(); //context to temporarily store variables for multi function ops.
	BIGNUM *n = BN_new(); //result of p*q
	BIGNUM *e = BN_new(); //public key for encryption
	BIGNUM *d = BN_new(); //private key for decryption, used to verify
	BIGNUM *mesHex = BN_new(); //hexadecimal form of the ASCII plaintext
	BIGNUM *cipHex = BN_new(); //final ciphertext

	//now initialize variables that were given to us from the seed document
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&mesHex, "4120746f702073656372657421"); //derived from the seed document above

	//Use the formula  cipHex = mesHex^e mod n to find ciphertext
	BN_mod_exp(cipHex, mesHex, e, n, ctx);

	//now call the print function
	printBN("", cipHex);
	
	return 0;
}


