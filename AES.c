#include <stdio.h>
#include <assert.h>
#include <string.h>
//#include <conio.h>
#include <stdint.h>
#include <stdio.h>

#ifndef AES_128_H
#define AES_128_H


#define AES_BLOCK_SIZE      16
#define AES_ROUNDS          10  // 12, 14
#define AES_ROUND_KEY_SIZE  176 // AES-128 has 10 rounds, and there is a AddRoundKey before first round. (10+1)x16=176.

//#define AES_ROUND_KEY_SIZE  704

/**
 * @purpose:            Key schedule for AES-128
 * @par[in]key:         16 bytes of master keys
 * @par[out]roundkeys:  176 bytes of round keys
 */
void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys);

/**
 * @purpose:            Encryption. The length of plain and cipher should be one block (16 bytes).
 *                      The plaintext and ciphertext may point to the same memory
 * @par[in]roundkeys:   round keys
 * @par[in]plaintext:   plain text
 * @par[out]ciphertext: cipher text
 */
void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);

/**
 * @purpose:            Decryption. The length of plain and cipher should be one block (16 bytes).
 *                      The ciphertext and plaintext may point to the same memory
 * @par[in]roundkeys:   round keys
 * @par[in]ciphertext:  cipher text
 * @par[out]plaintext:  plain text
 */
void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext);

#endif

/*
 * round constants
 */
static uint8_t RC[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * Sbox
 */
static uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/*
 * Inverse Sboxs
 */
static uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

/**
 * https://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * We do use mul2(int8_t a) but not mul(uint8_t a, uint8_t b)
 * just in order to get a higher speed.
 */
static inline uint8_t mul2(uint8_t a) {
    return (a&0x80) ? ((a<<1)^0x1b) : (a<<1);
}

/**
 * @purpose:    ShiftRows
 * @descrption:
 *  Row0: s0  s4  s8  s12   <<< 0 byte
 *  Row1: s1  s5  s9  s13   <<< 1 byte
 *  Row2: s2  s6  s10 s14   <<< 2 bytes
 *  Row3: s3  s7  s11 s15   <<< 3 bytes
 */
static void shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+1);
    *(state+1)  = *(state+5);
    *(state+5)  = *(state+9);
    *(state+9)  = *(state+13);
    *(state+13) = temp;
    // row2
    temp        = *(state+2);
    *(state+2)  = *(state+10);
    *(state+10) = temp;
    temp        = *(state+6);
    *(state+6)  = *(state+14);
    *(state+14) = temp;
    // row3
    temp        = *(state+15);
    *(state+15) = *(state+11);
    *(state+11) = *(state+7);
    *(state+7)  = *(state+3);
    *(state+3)  = temp;
}

/**
 * @purpose:    Inverse ShiftRows
 * @description
 *  Row0: s0  s4  s8  s12   >>> 0 byte
 *  Row1: s1  s5  s9  s13   >>> 1 byte
 *  Row2: s2  s6  s10 s14   >>> 2 bytes
 *  Row3: s3  s7  s11 s15   >>> 3 bytes
 */
static void inv_shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+13);
    *(state+13) = *(state+9);
    *(state+9)  = *(state+5);
    *(state+5)  = *(state+1);
    *(state+1)  = temp;
    // row2
    temp        = *(state+14);
    *(state+14) = *(state+6);
    *(state+6)  = temp;
    temp        = *(state+10);
    *(state+10) = *(state+2);
    *(state+2)  = temp;
    // row3
    temp        = *(state+3);
    *(state+3)  = *(state+7);
    *(state+7)  = *(state+11);
    *(state+11) = *(state+15);
    *(state+15) = temp;
}

void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys) {

    uint8_t temp[4];
    uint8_t *last4bytes; // point to the last 4 bytes of one round
    uint8_t *lastround;
    uint8_t i;

    for (i = 0; i < 16; ++i) {
        *roundkeys++ = *key++;
    }

    last4bytes = roundkeys-4;
    for (i = 0; i < AES_ROUNDS; ++i) {
        // k0-k3 for next round
        temp[3] = SBOX[*last4bytes++];
        temp[0] = SBOX[*last4bytes++];
        temp[1] = SBOX[*last4bytes++];
        temp[2] = SBOX[*last4bytes++];
        temp[0] ^= RC[i];
        lastround = roundkeys-16;
        *roundkeys++ = temp[0] ^ *lastround++;
        *roundkeys++ = temp[1] ^ *lastround++;
        *roundkeys++ = temp[2] ^ *lastround++;
        *roundkeys++ = temp[3] ^ *lastround++;
        // k4-k7 for next round        
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k8-k11 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k12-k15 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
    }
}

void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext) {

    uint8_t tmp[16], t;
    uint8_t i, j;

    // first AddRoundKey
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(ciphertext+i) = *(plaintext+i) ^ *roundkeys++;
    }

    // 9 rounds
    for (j = 1; j < AES_ROUNDS; ++j) {

        // SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(tmp+i) = SBOX[*(ciphertext+i)];
        }
        shift_rows(tmp);
        /*
         * MixColumns 
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01] . [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i+=4)  {
            t = tmp[i] ^ tmp[i+1] ^ tmp[i+2] ^ tmp[i+3];
            ciphertext[i]   = mul2(tmp[i]   ^ tmp[i+1]) ^ tmp[i]   ^ t;
            ciphertext[i+1] = mul2(tmp[i+1] ^ tmp[i+2]) ^ tmp[i+1] ^ t;
            ciphertext[i+2] = mul2(tmp[i+2] ^ tmp[i+3]) ^ tmp[i+2] ^ t;
            ciphertext[i+3] = mul2(tmp[i+3] ^ tmp[i]  ) ^ tmp[i+3] ^ t;
        }

        // AddRoundKey
        for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
            *(ciphertext+i) ^= *roundkeys++;
        }

    }
    
    // last round
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(ciphertext+i) = SBOX[*(ciphertext+i)];
    }
    shift_rows(ciphertext);
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(ciphertext+i) ^= *roundkeys++;
    }

}

void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext) {

    uint8_t tmp[16];
    uint8_t t, u, v;
    uint8_t i, j;

    roundkeys += 160;

    // first round
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(plaintext+i) = *(ciphertext+i) ^ *(roundkeys+i);
    }
    roundkeys -= 16;
    inv_shift_rows(plaintext);
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext+i) = INV_SBOX[*(plaintext+i)];
    }

    for (j = 1; j < AES_ROUNDS; ++j) {
        
        // Inverse AddRoundKey
        for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
            *(tmp+i) = *(plaintext+i) ^ *(roundkeys+i);
        }
        
        /*
         * Inverse MixColumns
         * [0e 0b 0d 09]   [s0  s4  s8  s12]
         * [09 0e 0b 0d] . [s1  s5  s9  s13]
         * [0d 09 0e 0b]   [s2  s6  s10 s14]
         * [0b 0d 09 0e]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i+=4) {
            t = tmp[i] ^ tmp[i+1] ^ tmp[i+2] ^ tmp[i+3];
            plaintext[i]   = t ^ tmp[i]   ^ mul2(tmp[i]   ^ tmp[i+1]);
            plaintext[i+1] = t ^ tmp[i+1] ^ mul2(tmp[i+1] ^ tmp[i+2]);
            plaintext[i+2] = t ^ tmp[i+2] ^ mul2(tmp[i+2] ^ tmp[i+3]);
            plaintext[i+3] = t ^ tmp[i+3] ^ mul2(tmp[i+3] ^ tmp[i]);
            u = mul2(mul2(tmp[i]   ^ tmp[i+2]));
            v = mul2(mul2(tmp[i+1] ^ tmp[i+3]));
            t = mul2(u ^ v);
            plaintext[i]   ^= t ^ u;
            plaintext[i+1] ^= t ^ v;
            plaintext[i+2] ^= t ^ u;
            plaintext[i+3] ^= t ^ v;
        }
        
        // Inverse ShiftRows
        inv_shift_rows(plaintext);
        
        // Inverse SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            *(plaintext+i) = INV_SBOX[*(plaintext+i)];
        }

        roundkeys -= 16;

    }

    // last AddRoundKey
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(plaintext+i) ^= *(roundkeys+i);
    }

}

int main(int argc, char *argv[]) {

   
    int i;
	uint8_t k, r;

	/* 128 bit key */
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,

	};

    uint8_t plaintext[17];

	uint8_t ciphertext[AES_BLOCK_SIZE];

	const uint8_t const_cipher[AES_BLOCK_SIZE] = {
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
	};

	uint8_t roundkeys[AES_ROUND_KEY_SIZE];

	// Data yang akan dikirim dan dienkrip dengan total jumlah 112 characters
  	// char PT[112];
	// printf("Type: ");
	// scanf("%s", PT);
	//char PT[112]="aaaaaaaaaaaaaaa bbbbbbbbbbbbbbbb ccccccccccccccc ddddddddddddddd eeeeeeeeeeeeeee fffffffffffffff ggggggggggggggg";
	char PT[112]="Pesan rahasia, semua pesawat tempur segera take off, menyerang sasaran di posisi -107.1288863 7.39893938;1233455555 xxxxxx";

	
	//PT_1 s.d PT_7 menyimpan data hasil pemisahan data strng menjadi 7 blok, masing-masing blok 16 karakter
	char PT_1[17];
	char PT_2[17];
	char PT_3[17];
	char PT_4[17];
	char PT_5[17];
	char PT_6[17];
	char PT_7[17];
	
	//CT_1 s.d CT_7 menyimpan data hasil pemisahan data strng terenkripsi menjadi 7 blok, masing-masing blok 16 karakter
	char CT_1[17];
	char CT_2[17];
	char CT_3[17];
	char CT_4[17];
	char CT_5[17];
	char CT_6[17];
	char CT_7[17];
 	 
	// c_1 s.d c_7 menyimpan Ciphertex dalam format Hexa pada proses ENKRIPSI
   	uint8_t c_1[17];
   	uint8_t c_2[17];
   	uint8_t c_3[17];
   	uint8_t c_4[17];
   	uint8_t c_5[17];
   	uint8_t c_6[17];
   	uint8_t c_7[17];
	
	// d_1 s.d d_7 menyimpan hasil enkripsi (Ciphertext) dalam format string
	unsigned char d_1[17];
    unsigned char d_2[17];
    unsigned char d_3[17];
    unsigned char d_4[17];
    unsigned char d_5[17];
    unsigned char d_6[17];
    unsigned char d_7[17];
   
   // e_1 s.d e_8 menyimpan hasil enskripsi (Ciphertext) dalam format Hexa pada proses DEKRIPSI
    uint8_t e_1[17];
    uint8_t e_2[17];
    uint8_t e_3[17];
    uint8_t e_4[17];
    uint8_t e_5[17];
    uint8_t e_6[17];
    uint8_t e_7[17];
	
	
	//PT_D1 s.d PT_D7 untuk menyimpan data hasil dekripsi pemisahan menjadi blok   
    char PT_D1[17];
	char PT_D2[17];
	char PT_D3[17];
	char PT_D4[17];
	char PT_D5[17];
	char PT_D6[17];
	char PT_D7[17];
    
    char g[112]; // string gabungan hasil dekrip
    char ct_gab[112]; //string gabungan hasil enkrip
   
	printf("\n------------------------ 1. Plain text, yaitu data teks yang akan dikirimkan (112 karakter) ----------------------\n");
	printf("\n");
	printf("%s  ",PT);
  
  	//Data PT, dibagi menjadi 7 blok data, masing-masing blok data terdiri dari 16 byte/character
	  
    for (i=0;i<=15;i++){	// Blok1 dengan karakter 0-15
    	PT_1[i]= PT[i];
		PT_2[i]= PT[i+16];
		PT_3[i]= PT[i+32];
		PT_4[i]= PT[i+48];
		PT_5[i]= PT[i+64];
		PT_6[i]= PT[i+80];
		PT_7[i]= PT[i+96];
	}
    
	PT_1[16] = '\0';   
	PT_2[16] = '\0';
	PT_3[16] = '\0';
	PT_4[16] = '\0';
	PT_5[16] = '\0';
	PT_6[16] = '\0';
	PT_7[16] = '\0';

    printf("\n");
	printf("\n------------------------ 2. Data dipisah dalam 7 blok, masing-masing 16 byte/char --------------------------------\n");
  	printf("\nDATA 1 : %s",PT_1);
    printf("\nDATA 2 : %s",PT_2);
	printf("\nDATA 3 : %s",PT_3);	
	printf("\nDATA 4 : %s",PT_4);
	printf("\nDATA 5 : %s",PT_5);
	printf("\nDATA 6 : %s",PT_6);
	printf("\nDATA 7 : %s",PT_7);
 

	//// key schedule yang digunakan////
	aes_key_schedule_128(key, roundkeys); //Tambah time schedule
	for ( r = 0; r <= AES_ROUNDS; r++ ) {
		for (i = 0; i < AES_BLOCK_SIZE; i++) {
		}
	}

	////////////////////////////////////////////////////////////////////////// PROSES ENKRIPSI//////////////////////////////////////

	printf("\n");
	printf("\n------------------------------- 3. Hasil enkripsi masing-masing blok dalam format Hexa ---------------------------\n");
 	printf("\n");
	// enkripsi data 1
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		plaintext[i]=PT_1[i];
	}
	aes_encrypt_128(roundkeys, plaintext, ciphertext); //Data 1 dari hexa di rubah dirubah menjadi cipher-hex
	printf("Ciphertext (DATA 1):  ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		c_1[i]=ciphertext[i];
		printf("%2x", c_1[i]);
	}
	if ( AES_BLOCK_SIZE != i ) { printf("    ENCRYPT WRONG\n"); } 
	else { printf("    ENCRYPT CORRECT\n"); }
    
    // enkripsi data 2
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
		plaintext[i]=PT_2[i];
	}
    aes_encrypt_128(roundkeys, plaintext, ciphertext); //Data 2 dari hexa di rubah dirubah menjadi cipher-hex
	printf("Ciphertext (DATA 2):  ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		c_2[i]=ciphertext[i];
		printf("%2x", c_2[i]);
	}
	if ( AES_BLOCK_SIZE != i ) { printf("   ENCRYPT WRONG\n"); }
	else { printf("    ENCRYPT CORRECT\n"); }

	// enkripsi data 3
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
    	plaintext[i]=PT_3[i];
	}
   	aes_encrypt_128(roundkeys, plaintext, ciphertext); //Data 3 dari hexa di rubah dirubah menjadi cipher-hex
	printf("Ciphertext (DATA 3):  ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		c_3[i]=ciphertext[i];
		printf("%2x", c_3[i]);
	}
	if ( AES_BLOCK_SIZE != i ) { printf("    ENCRYPT WRONG\n"); }
	else { printf("    ENCRYPT CORRECT\n"); }


	// enkripsi data 4  
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
    	plaintext[i]=PT_4[i];
	}
	aes_encrypt_128(roundkeys, plaintext, ciphertext); //Data 4 dari hexa di rubah dirubah menjadi cipher-hex
	printf("Ciphertext (DATA 4):  ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		c_4[i]=ciphertext[i];
		printf("%2x", c_4[i]);
	}
	if ( AES_BLOCK_SIZE != i ) { printf("    ENCRYPT WRONG\n"); }
	else { printf("    ENCRYPT CORRECT\n"); }
    
    // enkripsi data 5
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		plaintext[i]=PT_5[i];
	}
    aes_encrypt_128(roundkeys, plaintext, ciphertext); //Data 5 dari hexa di rubah dirubah menjadi cipher-hex
	printf("Ciphertext (DATA 5):  ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		c_5[i]=ciphertext[i];
		printf("%2x", c_5[i]);
	}
	if ( AES_BLOCK_SIZE != i ) { printf("    ENCRYPT WRONG\n"); }
	else { printf("    ENCRYPT CORRECT\n"); }


	// enkripsi data 6
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		plaintext[i]=PT_6[i];
	}
    aes_encrypt_128(roundkeys, plaintext, ciphertext); //Data 6 dari hexa di rubah dirubah menjadi cipher-hex
	printf("Ciphertext (DATA 6):  ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		c_6[i]=ciphertext[i];
		printf("%2x", c_6[i]);
	}
	if ( AES_BLOCK_SIZE != i ) { printf("    ENCRYPT WRONG\n"); }
	else { printf("    ENCRYPT CORRECT\n"); }

	// enkripsi data 7
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		plaintext[i]=PT_7[i];
	}
    aes_encrypt_128(roundkeys, plaintext, ciphertext); //Data 7 dari hexa di rubah dirubah menjadi cipher-hex
	printf("Ciphertext (DATA 7):  ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		c_7[i]=ciphertext[i];
		printf("%2x", c_7[i]);
	}
	if ( AES_BLOCK_SIZE != i ) { printf("    ENCRYPT WRONG"); }
	else { printf("    ENCRYPT CORRECT"); }
	
	 
   printf("\n");
   printf("\n------------------------------- 4. Hasil enkripsi masing-masing blok dalam format string --------------------------\n"); 
    // Konversi chiper text dari HEXA ke STRING 
   printf("\n");
	// data 1
	printf("Ciphertext (DATA 1):  ");
	for(i=0; i<AES_BLOCK_SIZE; i++){
        d_1[i] = c_1[i];
		printf("%c ", d_1[i]);
	}

    printf("\n");
    
    // data 2 
	printf("Ciphertext (DATA 2):  ");	//konversi string-hex dari data 2 
	for(i=0; i<AES_BLOCK_SIZE; i++){
        d_2[i] = c_2[i];
		printf("%c ", d_2[i]);
	}
		
    printf("\n");

	// data 3
	printf("Ciphertext (DATA 3):  ");	//konversi string-hex dari data 3  
	for(i=0; i<AES_BLOCK_SIZE; i++){
        d_3[i] = c_3[i];
		printf("%c ", d_3[i]);
	}    

    printf("\n");

	// data 4
	printf("Ciphertext (DATA 4):  ");	//konversi string-hex dari data 4  
	for(i=0; i<AES_BLOCK_SIZE; i++){
        d_4[i] = c_4[i];
		printf("%c ", d_4[i]);
	}    

	printf("\n");

	// data 5
	printf("Ciphertext (DATA 5):  ");	//konversi string-hex dari data 5  
	for(i=0; i<AES_BLOCK_SIZE; i++){
        d_5[i] = c_5[i];
		printf("%c ", d_5[i]);	
	}    

	printf("\n");

	// data 6 
	printf("Ciphertext (DATA 6):  ");	//konversi string-hex dari data 6  
	for(i=0; i<AES_BLOCK_SIZE; i++){
        d_6[i] = c_6[i];
		printf("%c ", d_6[i]);	
	}    

	printf("\n");

	// data 7 
	printf("Ciphertext (DATA 7):  ");	//konversi string-hex dari data 7  
	for(i=0; i<AES_BLOCK_SIZE; i++){
        d_7[i] = c_7[i];
		printf("%c ", d_7[i]);	
	}	

	
	// Gabungan data dari data 1 s/d data 7
	printf("\n");	
	printf("\n------------------------------- 5. Data Hasil enkripsi setelah digabung dalam satu paket data ---------------------\n");
	printf("\n");
	ct_gab[0]='\0';
   
    for (i=0; i<=15; i++){
	 ct_gab[i] = d_1[i];
	 ct_gab[i+16] = d_2[i];
	 ct_gab[i+32] = d_3[i];
	 ct_gab[i+48] = d_4[i];
	 ct_gab[i+64] = d_5[i];
	 ct_gab[i+80] = d_6[i];
	 ct_gab[i+96] = d_7[i];
	}


	ct_gab[112]='\0';
  	printf(" %s \n",ct_gab);
 
	printf("\n\n...........................................data dalam jaringan komunikasi radio...................................");

	//// ENKRIP SELESAI DI SINI/////

	///////////////////////////////////////////////////////////////////////////////////////MULAI DEKRIPSI///////////////////////////////////

	// Bagi data ter-enkripsi menjadi 7 blok
	CT_1[0] = '\0';   
	CT_2[0] = '\0';
	CT_3[0] = '\0';
	CT_4[0] = '\0';
	CT_5[0] = '\0';
	CT_6[0] = '\0';
	CT_7[0] = '\0';

	for (i=0;i<=15;i++){	// Blok1 dengan karakter 0-15
    	CT_1[i]= ct_gab[i];
		CT_2[i]= ct_gab[i+16];
		CT_3[i]= ct_gab[i+32];
		CT_4[i]= ct_gab[i+48];
		CT_5[i]= ct_gab[i+64];
		CT_6[i]= ct_gab[i+80];
		CT_7[i]= ct_gab[i+96];
	}
    
	CT_1[16] = '\0';   
	CT_2[16] = '\0';
	CT_3[16] = '\0';
	CT_4[16] = '\0';
	CT_5[16] = '\0';
	CT_6[16] = '\0';
	CT_7[16] = '\0';

    printf("\n");
	printf("\n------------------------------- 6. Data terenkripsi diterima dan dipilah menjasi 7 blok --------------------------\n");
  
  	printf("\nDATA 1 : %s",CT_1);
    printf("\nDATA 2 : %s",CT_2);
	printf("\nDATA 3 : %s",CT_3);	
	printf("\nDATA 4 : %s",CT_4);
	printf("\nDATA 5 : %s",CT_5);
	printf("\nDATA 6 : %s",CT_6);
	printf("\nDATA 7 : %s",CT_7);
	

	//print Hexa ke Ciphertext pada masing-masing data yang telah dibagi- bagi

    printf("\n");
	printf("\n------------------------------- 7. Data terenkripsi masing-masing blok di rubah dalam bentuk Hexa-----------------\n");
 
	for(i=0; i<AES_BLOCK_SIZE; i++){
 	   e_1[i] = CT_1[i];
	}
	printf("\nDATA 1 :  "); //String to Cipher Data 1
    for(i=0; i<AES_BLOCK_SIZE; i++){
     	printf("%2x ", e_1[i]);
	}
	
	for(i=0; i<AES_BLOCK_SIZE; i++){
 	   e_2[i] = CT_2[i];
 	}
	printf("\nDATA 2 :  ");	 //String to Cipher Data 2
    for(i=0; i<AES_BLOCK_SIZE; i++){
        printf("%2x ", e_2[i]);
	}
	
	for(i=0; i<AES_BLOCK_SIZE; i++){
 	   e_3[i] = CT_3[i];
	}
	printf("\nDATA 3 :  "); //String to Cipher Data 3
    for(i=0; i<AES_BLOCK_SIZE; i++){
        printf("%2x ", e_3[i]);
	}
	
	for(i=0; i<AES_BLOCK_SIZE; i++){
 	   e_4[i] = CT_4[i];
	}
	printf("\nDATA 4 :  ");	 //String to Cipher Data 4
    for(i=0; i<AES_BLOCK_SIZE; i++){
        printf("%2x ", e_4[i]);
	}
	
	for(i=0; i<AES_BLOCK_SIZE; i++){
 	   e_5[i] = CT_5[i];
	}
	printf("\nDATA 5 :  ");	 //String to Cipher Data 5
    for(i=0; i<AES_BLOCK_SIZE; i++){
        printf("%2x ", e_5[i]);
	}
	
	for(i=0; i<AES_BLOCK_SIZE; i++){
 	   e_6[i] = CT_6[i];
	}
	printf("\nDATA 6 :  ");	 //String to Cipher Data 6
    for(i=0; i<AES_BLOCK_SIZE; i++){
        printf("%2x ", e_6[i]);
	}
	
		for(i=0; i<AES_BLOCK_SIZE; i++){
 	   e_7[i] = CT_7[i];
	}
	printf("\nDATA 7 :  ");	 //String to Cipher Data 7
    for(i=0; i<AES_BLOCK_SIZE; i++){
        printf("%2x ", e_7[i]);
	}
	
	
/////////////////////////////////////////////////////////PROSES DEKRIPSI DARI CIPHER KE DATA ASLI DATA 1 S/D DATA 7////////////////////////

    printf("\n");
	printf("\n------------------------------- 8. Data terenkripsi masing-masing blok di dekripsi -------------------------------\n");
 	printf("\n");
	//Proses dekripsi data 1
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		ciphertext[i]=e_1[i];
	}
	aes_decrypt_128(roundkeys, ciphertext, plaintext);
	printf("Plaintext (DATA 1) : ");
		for (i = 0; i < AES_BLOCK_SIZE; i++) {
			PT_D1[i]=plaintext[i];
			printf("%c ", plaintext[i]);
	}
	if ( AES_BLOCK_SIZE != i ) { printf("		DECRYPT WRONG"); }
		else { printf("		DECRYPT CORRECT"); }


	//Proses dekripsi data 2
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
	ciphertext[i]=e_2[i];
	}
	aes_decrypt_128(roundkeys, ciphertext, plaintext);
	printf("\nPlaintext (DATA 2) : ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%c ", plaintext[i]);
		PT_D2[i]=plaintext[i];
	}
	if ( AES_BLOCK_SIZE != i ) { printf("		DECRYPT WRONG"); }
		else { printf("		DECRYPT CORRECT"); }


	//Proses dekripsi data 3
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
	ciphertext[i]=e_3[i];
	}    
	aes_decrypt_128(roundkeys, ciphertext, plaintext);
	printf("\nPlaintext (DATA 3) : ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%c ", plaintext[i]);
		PT_D3[i]=plaintext[i];
	}
	if ( AES_BLOCK_SIZE != i ) { printf("		DECRYPT WRONG"); }
		else { printf("		DECRYPT CORRECT"); }

	
	//Proses dekripsi data 4
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		ciphertext[i]=e_4[i];
	}
	aes_decrypt_128(roundkeys, ciphertext, plaintext);
	printf("\nPlaintext (DATA 4) : ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%c ", plaintext[i]);
		PT_D4[i]=plaintext[i];	
	}
	if ( AES_BLOCK_SIZE != i ) { printf("		DECRYPT WRONG"); }
		else { printf("		DECRYPT CORRECT"); }
	
	
	//Proses dekripsi data 5
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		ciphertext[i]=e_5[i];
	}
	aes_decrypt_128(roundkeys, ciphertext, plaintext);
	printf("\nPlaintext (DATA 5) : ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%c ", plaintext[i]);
		PT_D5[i]=plaintext[i];
	}
	if ( AES_BLOCK_SIZE != i ) { printf("		DECRYPT WRONG"); }
		else { printf("		DECRYPT CORRECT"); }

	
	//Proses dekripsi data 6
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		ciphertext[i]=e_6[i];
	}
	aes_decrypt_128(roundkeys, ciphertext, plaintext);
	printf("\nPlaintext (DATA 6) : ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%c ", plaintext[i]);
		PT_D6[i]=plaintext[i];
	}
	if ( AES_BLOCK_SIZE != i ) { printf("		DECRYPT WRONG"); }
		else { printf("		DECRYPT CORRECT"); }


	//Proses dekripsi data 7
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		ciphertext[i]=e_7[i];
	}
	aes_decrypt_128(roundkeys, ciphertext, plaintext);
	printf("\nPlaintext (DATA 7) : ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%c ", plaintext[i]);
		PT_D7[i]=plaintext[i];
	}
	if ( AES_BLOCK_SIZE != i ) { printf("		DECRYPT WRONG"); }
		else { printf("		DECRYPT CORRECT"); }

	PT_D1[16] = '\0'; 
	PT_D2[16] = '\0';
	PT_D3[16] = '\0';
	PT_D4[16] = '\0';
	PT_D5[16] = '\0';
	PT_D6[16] = '\0';
	PT_D7[16] = '\0';

///////////////////////////////////////////////////////////////////////////////AKHIR DEKRIPSI///////////////////////////////////////////

    printf("\n");
	printf("\n------------ 9. Hasil dekrispsi masig-masing blok digabung menjadi sebuah data yang sesui dengan data awal--------\n");

// Gabungan data hasil dekripsi
    printf("\n");
	g[0]='\0';
	strcat(g,PT_D1);
	strcat(g,PT_D2);
  	strcat(g,PT_D3);
  	strcat(g,PT_D4);
 	strcat(g,PT_D5);
	strcat(g,PT_D6);
	strcat(g,PT_D7);
   

	printf("%s",g);
	printf("\n\n");
	
	getchar();
   return 0;
}

