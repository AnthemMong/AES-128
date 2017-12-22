# include<stdio.h>
# include<stdlib.h>
# include<memory.h>
# include"aes-128.h"

int main(int argc, char* argv[])
{
    uint8_t message[16], ciphertext[16], key[16], result[16];
    
    printf("message: ");
    fgets(message, 16, stdin);
    fflush(stdin);
    printf("message: ");
    debug_print(message, 16);

    printf("key: ");
    fgets(key, 16, stdin);
    printf("key: ");
    debug_print(key, 16);

    en_aes(message, key, ciphertext);
    debug_print(ciphertext, 16);
    de_aes(message, key, ciphertext);
    debug_print(message, 16);

    return 0;
}