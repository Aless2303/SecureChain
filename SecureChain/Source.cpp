#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>

int main() {
	AES_KEY aesKey;
	unsigned char userKey[] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	AES_set_encrypt_key(userKey, 128, &aesKey);

	unsigned char inText[] = { 't','e','s','t' };
	unsigned char enc[16];
	unsigned char dec[16];

	AES_ecb_encrypt(inText, enc, &aesKey, AES_ENCRYPT);
	for (int i = 0; i < 16; i++) {
		printf("%02x", enc[i]);
	}
	printf("\n");

	system("pause");
	return 0;
}
