#include<bits/stdc++.h>
#include "xchacha20.h"
using namespace std;

/** hchacha an intermediary step towards XChaCha20 based on the
 * construction and security proof used to create XSalsa20.
 * @param out Holds output of hchacha
 * @param in The input to process with hchacha
 * @param k The key to use with hchacha
 *
 */
void xchacha_hchacha20(uint8_t *out, const uint8_t *in, const uint8_t *k){
    int i;
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t x8, x9, x10, x11, x12, x13, x14, x15;

    /* XChaCha Constant */
    x0 = 0x61707865;
    x1 = 0x3320646e;
    x2 = 0x79622d32;
    x3 = 0x6b206574;

    x4  = U8TO32_LITTLE(k +  0);
    x5  = U8TO32_LITTLE(k +  4);
    x6  = U8TO32_LITTLE(k +  8);
    x7  = U8TO32_LITTLE(k + 12);
    x8  = U8TO32_LITTLE(k + 16);
    x9  = U8TO32_LITTLE(k + 20);
    x10 = U8TO32_LITTLE(k + 24);
    x11 = U8TO32_LITTLE(k + 28);
    x12 = U8TO32_LITTLE(in +  0);
    x13 = U8TO32_LITTLE(in +  4);
    x14 = U8TO32_LITTLE(in +  8);
    x15 = U8TO32_LITTLE(in + 12);

    for (i = 0; i < 10; i++){
        QUARTERROUND(x0, x4,  x8, x12);
        QUARTERROUND(x1, x5,  x9, x13);
        QUARTERROUND(x2, x6, x10, x14);
        QUARTERROUND(x3, x7, x11, x15);
        QUARTERROUND(x0, x5, x10, x15);
        QUARTERROUND(x1, x6, x11, x12);
        QUARTERROUND(x2, x7,  x8, x13);
        QUARTERROUND(x3, x4,  x9, x14);
    }

    U32TO8_LITTLE(out +  0, x0);
    U32TO8_LITTLE(out +  4, x1);
    U32TO8_LITTLE(out +  8, x2);
    U32TO8_LITTLE(out + 12, x3);
    U32TO8_LITTLE(out + 16, x12);
    U32TO8_LITTLE(out + 20, x13);
    U32TO8_LITTLE(out + 24, x14);
    U32TO8_LITTLE(out + 28, x15);
}


/** Setup the XChaCha20 encryption key
 * @param x The XChaCha20 Context to use
 * @param k A buffer holding the encryption key to use
 * @note Valid key sizes are 256 bits, and the only valid IV size
 * is 192 bits.
 *
 */
void xchacha_keysetup(XChaCha_ctx *ctx, const uint8_t *k, uint8_t *iv){
    /* The sub-key to use */
    uint8_t k2[32];

    /* Generate the sub-key to use from the 256-bit key and 192-bit iv
     * We then use this sub-key and the last 8 bytes of the iv
     * as normal.
     */
    xchacha_hchacha20(k2, iv, k);


    ctx->input[0] = 0x61707865;
    ctx->input[1] = 0x3320646e;
    ctx->input[2] = 0x79622d32;
    ctx->input[3] = 0x6b206574;
    ctx->input[4] = U8TO32_LITTLE(k2 + 0);
    ctx->input[5] = U8TO32_LITTLE(k2 + 4);
    ctx->input[6] = U8TO32_LITTLE(k2 + 8);
    ctx->input[7] = U8TO32_LITTLE(k2 + 12);
    ctx->input[8] = U8TO32_LITTLE(k2 + 16);
    ctx->input[9] = U8TO32_LITTLE(k2 + 20);
    ctx->input[10] = U8TO32_LITTLE(k2 + 24);
    ctx->input[11] = U8TO32_LITTLE(k2 + 28);
    ctx->input[12] = 0;			/* Internal counter */
    ctx->input[13] = 0;         /* Internal counter */
    ctx->input[14] = U8TO32_LITTLE(iv + 16);
    ctx->input[15] = U8TO32_LITTLE(iv + 20);
}


/** Set the internal counter to a specific number. Depending
 * on the specification, sometimes the counter is started at 1.
 * @param ctx The XChaCha context to modify
 * @param counter The number to set the counter to
 *
 */
void xchacha_set_counter(XChaCha_ctx *ctx, uint8_t *counter){
    ctx->input[12] = U8TO32_LITTLE(counter + 0);
    ctx->input[13] = U8TO32_LITTLE(counter + 4);
}


/** Encrypt data with the XChaCha20 stream cipher
 * @param x The XChaCha20 context with the cipher's state to use
 * @param m The plaintext to encrypt
 * @param c A buffer to hold the ciphertext created from the plaintext
 * @param bytes The length of the plaintext to encrypt
 * @note length of c must be >= the length of m otherwise a buffer
 * overflow will occur.
 *
 */
void xchacha_encrypt_bytes(XChaCha_ctx *ctx, const uint8_t *m, uint8_t *c, uint32_t bytes){
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    uint8_t *ctarget = NULL;
    uint8_t tmp[64];
    uint32_t i;

    if (!bytes) return;

    j0 = ctx->input[0];
    j1 = ctx->input[1];
    j2 = ctx->input[2];
    j3 = ctx->input[3];
    j4 = ctx->input[4];
    j5 = ctx->input[5];
    j6 = ctx->input[6];
    j7 = ctx->input[7];
    j8 = ctx->input[8];
    j9 = ctx->input[9];
    j10 = ctx->input[10];
    j11 = ctx->input[11];
    j12 = ctx->input[12];
    j13 = ctx->input[13];
    j14 = ctx->input[14];
    j15 = ctx->input[15];

    for (;;) {
        if (bytes < 64) {
            for (i = 0;i < bytes;++i)
                tmp[i] = m[i];
            m = tmp;
            ctarget = c;
            c = tmp;
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;

        /* Do 20 rounds instead of 8 */
        for (i = 20;i > 0;i -= 2) {
            QUARTERROUND( x0, x4, x8,x12)
            QUARTERROUND( x1, x5, x9,x13)
            QUARTERROUND( x2, x6,x10,x14)
            QUARTERROUND( x3, x7,x11,x15)
            QUARTERROUND( x0, x5,x10,x15)
            QUARTERROUND( x1, x6,x11,x12)
            QUARTERROUND( x2, x7, x8,x13)
            QUARTERROUND( x3, x4, x9,x14)
        }
        x0 = PLUS(x0,j0);
        x1 = PLUS(x1,j1);
        x2 = PLUS(x2,j2);
        x3 = PLUS(x3,j3);
        x4 = PLUS(x4,j4);
        x5 = PLUS(x5,j5);
        x6 = PLUS(x6,j6);
        x7 = PLUS(x7,j7);
        x8 = PLUS(x8,j8);
        x9 = PLUS(x9,j9);
        x10 = PLUS(x10,j10);
        x11 = PLUS(x11,j11);
        x12 = PLUS(x12,j12);
        x13 = PLUS(x13,j13);
        x14 = PLUS(x14,j14);
        x15 = PLUS(x15,j15);

        x0 = XOR(x0,U8TO32_LITTLE(m + 0));
        x1 = XOR(x1,U8TO32_LITTLE(m + 4));
        x2 = XOR(x2,U8TO32_LITTLE(m + 8));
        x3 = XOR(x3,U8TO32_LITTLE(m + 12));
        x4 = XOR(x4,U8TO32_LITTLE(m + 16));
        x5 = XOR(x5,U8TO32_LITTLE(m + 20));
        x6 = XOR(x6,U8TO32_LITTLE(m + 24));
        x7 = XOR(x7,U8TO32_LITTLE(m + 28));
        x8 = XOR(x8,U8TO32_LITTLE(m + 32));
        x9 = XOR(x9,U8TO32_LITTLE(m + 36));
        x10 = XOR(x10,U8TO32_LITTLE(m + 40));
        x11 = XOR(x11,U8TO32_LITTLE(m + 44));
        x12 = XOR(x12,U8TO32_LITTLE(m + 48));
        x13 = XOR(x13,U8TO32_LITTLE(m + 52));
        x14 = XOR(x14,U8TO32_LITTLE(m + 56));
        x15 = XOR(x15,U8TO32_LITTLE(m + 60));

        j12 = PLUSONE(j12);
        if (!j12) {
            j13 = PLUSONE(j13);
        }

        U32TO8_LITTLE(c + 0,x0);
        U32TO8_LITTLE(c + 4,x1);
        U32TO8_LITTLE(c + 8,x2);
        U32TO8_LITTLE(c + 12,x3);
        U32TO8_LITTLE(c + 16,x4);
        U32TO8_LITTLE(c + 20,x5);
        U32TO8_LITTLE(c + 24,x6);
        U32TO8_LITTLE(c + 28,x7);
        U32TO8_LITTLE(c + 32,x8);
        U32TO8_LITTLE(c + 36,x9);
        U32TO8_LITTLE(c + 40,x10);
        U32TO8_LITTLE(c + 44,x11);
        U32TO8_LITTLE(c + 48,x12);
        U32TO8_LITTLE(c + 52,x13);
        U32TO8_LITTLE(c + 56,x14);
        U32TO8_LITTLE(c + 60,x15);

        if (bytes <= 64) {
            if (bytes < 64) {
                for (i = 0;i < bytes;++i)
                    ctarget[i] = c[i];
            }
            ctx->input[12] = j12;
            ctx->input[13] = j13;
            return;
        }
        bytes -= 64;
        c += 64;
        m += 64;
    }
}


/** Generate a keystream from encrypting a zero byte plaintext
 * @param x The XChaCha context to use
 * @param stream A buffer to store the generated keystream
 * @param bytes The number of bytes of keystream to generate
 * @note Mostly for testing purposes
 *
 */
void xchacha_keystream_bytes(XChaCha_ctx *ctx, uint8_t *stream, uint32_t bytes){
    uint32_t i;

    for (i = 0;i < bytes;++i){
        stream[i] = 0;
    }

    xchacha_encrypt_bytes(ctx,stream,stream,bytes);
}

int strtoarrayc(string msg, uint8_t *ciphertext){
	int len = msg.length();
    for(int i=0;i<len;i++) ciphertext[i] = msg[i];
    return len;
}

void lltoarrayc(string C, long long *ckey, long long *civ){
	int m = 0,l = 0;
	while (5)
	{
		long long y = 0;
		while (C[m] != ' ' && C[m] != '\0')
		{
			y = (y * 10) + (C[m] - 48);
			m++;
		}
		m++;
		if(l<32) ckey[l]=y;
		else civ[l-32] = y;
		if (m >= C.length())
		{
			break;
		}
		l++;
	}
}

void lltouint(long long arr[], int n, uint8_t *arr2){
	for(int i=0;i<n;i++){
		arr2[i] = arr[i];
	}
}


long long int compute(long long int a,long long int m, long long int n)
{
	long long int r;
	long long int y = 1;

	while (m > 0)
	{
		r = m % 2;
		if (r == 1)
		{
			y = (y * a) % n;
		}
		a = a * a % n;
		m = m / 2;
	}

	return y;
}

void encryption()
{
	cout << "Key Encryption:\n";
	long long int e, n, i, l = 0, m = 0, j;
	long long int C1[100];
	cout << "Enter n:";
	cin >> n;
	getchar();
	cout << "Enter Public key e:";
	cin >> e;
	getchar();
	string C;
	ifstream plfile;
	plfile.open("keyfile", ios::in | ios::binary);

	if (plfile.is_open())
	{
		getline(plfile, C); // The first line of file is the key
		plfile.close();
	}

	else
		cout << "Unable to open file";

	for (i = 0; i < l; i++)
	{
		cout << C1[i];
	}
	while (5)
	{
		int y = 0;
		while (C[m] != ' ' && C[m] != '\0')
		{
			y = (y * 10) + (C[m] - 48);
			m++;
		}
		m++;
		C1[l] = y;
		if (m >= C.length())
		{
			break;
		}
		l++;
	}
	for (j = 0; j <= l; j++)
	{
		C1[j] = compute(C1[j], e, n);
	}
	cout << "\n";
	ofstream outfile;
	outfile.open("Key_Cipher.txt", ios::out | ios::binary);
	if (outfile.is_open())
	{
		for (int i = 0; i <= l; i++)
		{
			outfile << C1[i];
			outfile << " ";
		}
		outfile.close();
		cout << "Wrote encrypted key to file Key_Cipher.txt\n";
	}
}

int main()
{
	string msgstr;
	ifstream msgfile;
	msgfile.open("plaintext.txt", ios::in | ios::binary);
	if(msgfile.is_open()){
		getline(msgfile, msgstr);
		cout<<"Reading the message from plaintext.txt"<<endl;
		msgfile.close();
	}
	else cout<<"Unable to open msg.file";
	uint8_t *plaintext;
	if((plaintext = (uint8_t *)malloc(sizeof(uint8_t)*msgstr.length()))==NULL){
		return -1;
	}
	int text_len = strtoarrayc(msgstr, plaintext);
    // for(int i=0;i<text_len;i++) printf("%02x", plaintext[i]);
	//c:\Users\ffair\Downloads\plaintext.txt Read in the key
	string keystr;
	ifstream keyfile;
	long long key[32], iv[24];
	keyfile.open("keyfile", ios::in | ios::binary);

	if (keyfile.is_open())
	{
		getline(keyfile, keystr); // The first line of file should be the key
		cout << "Reading the key from keyfile" << endl;
		keyfile.close();
	}

	else
		cout << "Unable to open file";

	lltoarrayc(keystr, key, iv);
	uint8_t keyi[32], ivi[24];
	lltouint(key, 32, keyi);
	lltouint(iv, 24, ivi);
	XChaCha_ctx ctx;
    uint8_t *buffer2;
    // uint8_t buffer2[text_len];
    //  Allocate a buffer to hold our calculated ciphertext */
    if ((buffer2 = (uint8_t *)malloc(text_len * sizeof(uint8_t))) == NULL) {
        perror("malloc() error");
        return -1;
    }

    xchacha_keysetup(&ctx, keyi, ivi);
	xchacha_encrypt_bytes(&ctx, plaintext, buffer2, text_len);
	cout<<"Successfully Encrypted";
	ofstream outfile;
	outfile.open("ciphertext.txt", ios::out | ios::binary);
	if (outfile.is_open())
	{
		for(int i=0;i<text_len;i++){
			outfile<<(int)buffer2[i];
			outfile<<" ";
		}
		outfile.close();
		cout<<("Wrote Encrypted text to file ciphertext.txt\n");
	}
	// cout<<"Encrypted text in hex is:";
    // for(int i=0;i<text_len;i++) printf("%02x ", buffer2[i]);
    // printf("\n");
    encryption();
	return 0;
}
