# ifndef AES_128_H
# define AES_128_H

# include<stdint.h>

# define KEY_BYTE 16
# define LEFT_SHIFT 0X00
# define RIGHT_SHIFT 0X01

int en_aes(uint8_t* message, uint8_t* key, uint8_t* ciphertext);

int de_aes(uint8_t* message, uint8_t* key, uint8_t* ciphertext);

void print_bin(uint8_t* buff, int len);

void debug_print(uint8_t* buff, int len);

void debug_state_print(uint8_t state[4][4]);

# endif 