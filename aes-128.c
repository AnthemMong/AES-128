# include<stdio.h>
# include<stdlib.h>
# include<memory.h>
# include"aes-128.h"

extern uint8_t s_box[16][16];
extern uint8_t inv_s_box[16][16];
extern uint8_t m_box[4][4];
extern uint8_t inv_m_box[4][4];
extern uint8_t rcon[10][4];

int cyclic_shift(uint8_t* row, int bytes, int mode, uint8_t* newrow);
int long_xor(uint8_t* arg1, uint8_t* arg2, int bytes, uint8_t* result);
int key_expansion(uint8_t* key, uint8_t ex_keys[11][4][4]);
int subbytes(uint8_t state[4][4], uint8_t box[16][16], uint8_t newstate[4][4]);
int exch_rol_row(uint8_t* message, uint8_t state[4][4]);
int shift_row(uint8_t state[4][4], int mode, uint8_t newstate[4][4]);
int mix_columns(uint8_t state[4][4], uint8_t box[4][4], uint8_t newstate[4][4]);
int add_round_key(uint8_t state1[4][4], uint8_t state2[4][4], uint8_t newstate[4][4]);
uint8_t mutiplication(uint8_t arg1, uint8_t arg2);

//encryption
int en_aes(uint8_t* message, uint8_t* key, uint8_t* ciphertext)
{
    uint8_t ex_keys[11][4][4], state[4][4], cipher_tmp[4][4];
    int i;

    exch_rol_row(message, state);
    key_expansion(key, ex_keys);
    for (i = 0; i < 11; i++)
        exch_rol_row((uint8_t*)(ex_keys[i]), ex_keys[i]);
    
    add_round_key(state, ex_keys[0], cipher_tmp);
    for (i = 1; i < 11; i++)
    {
        subbytes(cipher_tmp, s_box, cipher_tmp);
        shift_row(cipher_tmp, LEFT_SHIFT, cipher_tmp);
        if (i != 10)
            mix_columns(cipher_tmp, m_box, cipher_tmp);
        add_round_key(cipher_tmp, ex_keys[i], cipher_tmp);
    }
    exch_rol_row((uint8_t*)cipher_tmp, cipher_tmp);
    memcpy(ciphertext, cipher_tmp, 16);
    return 1;
}
//deciphering
int de_aes(uint8_t* message, uint8_t* key, uint8_t* ciphertext)
{
    uint8_t ex_keys[11][4][4], state[4][4], message_tmp[4][4];
    int i, k;

    k = 10;
    exch_rol_row(ciphertext, state);
    key_expansion(key, ex_keys);

    for (i = 0; i < 11; i++)
        exch_rol_row((uint8_t*)(ex_keys[i]), ex_keys[i]);

    add_round_key(state, ex_keys[k--], message_tmp);
    printf("\n");
    for (i = 1; i < 11; i++)
    {
        shift_row(message_tmp, RIGHT_SHIFT, message_tmp);
        subbytes(message_tmp, inv_s_box, message_tmp);
        add_round_key(message_tmp, ex_keys[k--], message_tmp);
        if (i != 10)
            mix_columns(message_tmp, inv_m_box, message_tmp);
    }
    exch_rol_row((uint8_t*)message_tmp, message_tmp);
    memcpy(message, message_tmp, 16);
    return 1;
}

int key_expansion(uint8_t* key, uint8_t ex_keys[11][4][4])
{
    int i, k, h, col, row;
    int8_t tmp[4], *pre, mid[4], last[4];
    
    memcpy(ex_keys[0], key, 16);
    for (i = 1; i < 11; i++)
    {
        pre = ex_keys[i-1][0];
        for (k = 0; k < 4; k++)
        {
            memcpy(last, ex_keys[i -1][k], 4);
            if (k == 0)
            {
                cyclic_shift(ex_keys[i -1][3], 1, LEFT_SHIFT, tmp);
                for (h = 0; h < 4; h++)
                {
                    row = (tmp[h] & 0xF0) >> 4;
                    col = (tmp[h] & 0x0F);
                    mid[h] = s_box[row][col];
                }
                long_xor(mid, rcon[i -1], 4, last);
            }
            long_xor(last, pre, 4, tmp);
            memcpy(ex_keys[i][k], tmp, 4);
            pre = ex_keys[i][k];
        }
    }
    return 1;
}

//exhange the state's row and coloumn
int exch_rol_row(uint8_t* message, uint8_t state[4][4])
{
    uint8_t message_tmp[KEY_BYTE];
    int i, k;

    memcpy(message_tmp, message, KEY_BYTE);
    for (i = 0; i < 4; i++)
    {
        for (k = 0; k < 4; k++)
            state[i][k] = message_tmp[k * 4 + i];
    }
    return 0;
}

//subsitute bytes according to box;
int subbytes(uint8_t state[4][4], uint8_t box[16][16], uint8_t newstate[4][4])
{
    int col, row, i, k;
    uint8_t state_tmp[4][4];

    memcpy(state_tmp, state, 4 * 4);
    for (i = 0; i < 4; i++)
    {
        for (k = 0; k < 4; k++)
        {
            row = (state_tmp[i][k] & 0xF0) >> 4;
            col = (state_tmp[i][k] & 0x0F);
            newstate[i][k] = box[row][col];
        }
    }
    return 1;
}

int shift_row(uint8_t state[4][4], int mode, uint8_t newstate[4][4])
{
    uint8_t state_tmp[4][4];
    int i;

    memcpy(state_tmp, state, 16);
    for (i = 0; i < 4; i++)
    {
        if (i > 0)
            cyclic_shift(state_tmp[i], i, mode, newstate[i]);
        else
            memcpy(newstate[i], state_tmp[i], 4);
    }
    return 1;
}

int mix_columns(uint8_t state[4][4], uint8_t box[4][4], uint8_t newstate[4][4])
{
    int i, k;
    uint8_t tmp, state_tmp[4][4];

    memcpy(state_tmp, state, 16);
    for (i = 0; i < 4; i++)
    {
        for (k = 0; k < 4; k++)
        {
            newstate[k][i] = mutiplication(box[k][0], state_tmp[0][i]) ^
                mutiplication(box[k][1], state_tmp[1][i]) ^ 
                mutiplication(box[k][2], state_tmp[2][i]) ^
                mutiplication(box[k][3], state_tmp[3][i]);
        }
    }
    return 1;
}

int add_round_key(uint8_t state1[4][4], uint8_t state2[4][4], uint8_t newstate[4][4])
{
    int i, k;
    uint8_t state_tmp[4][4];

    memcpy(state_tmp, state1, 16);
    for (i = 0; i < 4; i++)
    {
        for (k = 0; k < 4; k++)
            newstate[i][k] = state_tmp[i][k] ^ state2[i][k];
    }
    return 1;
}

//GF(2^n) mutiplication
uint8_t mutiplication(uint8_t arg1, uint8_t arg2)
{
    int i, len;
    uint8_t mid_tmps[8], mask, result, tmp;

    mask = 0x01;
    tmp = arg1;
    for (i = 0, len = 0; i < 8; i++)
    {
        if (i == 0)
        {
            if ((mask & arg2) == mask)
                mid_tmps[len++] = tmp;
            mask = mask << 1;
            continue;
        }
        if ((tmp & 0x80) == 0x80)
            tmp = (tmp << 1) ^ 0x1b;
        else
            tmp = (tmp << 1);
        if ((mask & arg2) == mask)
            mid_tmps[len++] = tmp;
        mask = mask << 1;
    }

    if (len == 1)
        return mid_tmps[0];
    else if (len == 0)
        return 0x00;

    result = mid_tmps[0] ^ mid_tmps[1];
    for (i = 2; i < len; i++)
        result ^= mid_tmps[i];
    return result;
}

int long_xor(uint8_t* arg1, uint8_t* arg2, int bytes, uint8_t* result)
{
    int i;
    uint8_t arg1_tmp[bytes];

    memcpy(arg1_tmp, arg1, bytes);
    for (i = 0; i < bytes; i++)
        result[i] = arg1_tmp[i] ^ arg2[i];
    return 1; 
}

int cyclic_shift(uint8_t* row, int bytes, int mode, uint8_t* newrow)
{
    int i, n;
    uint8_t row_tmp[4];

    memcpy(row_tmp, row, 4);
    if (mode == LEFT_SHIFT)
    {
        for (i = 0, n = 0; i < 4; i++, n++)
            newrow[i] = row_tmp[(n + bytes) % 4];
    }
    else
    {
        for (i = 0, n = 4 ; i < 4; i++, n++)
            newrow[i] = row_tmp[(n - bytes) % 4];
    }
    return 1;
}

void print_bin(uint8_t* buff, int len)
{
    int i, j;
    uint8_t tmp, flag;

    for (i = 0; i < len; i++)
    {
        tmp = buff[i];
        for (j = 0; j < 8; j++)
        {
            flag = tmp << j;
            if ((flag & 0x80) == 0x80)
                printf("1");
            else
                printf("0");
        }
        printf(" ");
    }
    printf("\n");
}

void debug_print(uint8_t* buff, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		printf("%02x ", buff[i]);
	}
	printf("\n");
}

void debug_state_print(uint8_t state[4][4])
{
    int i, k;
    
    for(i = 0; i < 4; i++)
    {
        for (k = 0; k < 4; k++)
            printf("%02x ", state[i][k]);
        printf("\n");
    }
}