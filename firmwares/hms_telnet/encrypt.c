#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

const char USER_KEY[] = "84fc8e35f068c1ce08c041ebb0d4847c";

int main(int argc, char* argv[]){
  AES_KEY AESkey;
  const char* user_key = USER_KEY;
  const char* in_file = NULL;
  const char* out_file = NULL;
  int is_encryption = 0;

  int c;
  for (;;) {
    int c = getopt(argc, argv, "e:d:o:k:");
    if (c == -1) {
      break;
    }

    switch (c) {
      case 'e':
        is_encryption = 1;
        in_file = optarg;
        break;

      case 'd':
        is_encryption = 0;
        in_file = optarg;
        break;

      case 'o':
        out_file = optarg;
        break;

      case 'k':
        user_key = optarg;
        break;
    
      default:
        break;
    }
  }

  if (strlen(user_key) != 32) {
    printf("User key [%s] must be 32 characters!\n", user_key);
    return -1;
  }

  if (in_file == NULL) {
    printf("Input file not specified\n");
    return -2;
  }

  if (out_file == NULL) {
    printf("Output file not specified\n");
    return -3;
  }

  if (is_encryption) {
    AES_set_encrypt_key((const unsigned char *)user_key, strlen(user_key) * 8, &AESkey);
  } else {
    AES_set_decrypt_key((const unsigned char *)user_key, strlen(user_key) * 8, &AESkey);
  }

  uint8_t aes_iv[0x40];
  uint8_t in_buf[0x40], out_buf[0x40];

  FILE* fp_in = fopen(in_file, "rb");
  FILE* fp_out = fopen(out_file, "wb");

  for (;;) {
    size_t len = fread(in_buf, 1, sizeof(in_buf), fp_in);
    if (len == 0) {
      break;
    }

    AES_cbc_encrypt(in_buf, out_buf, len, &AESkey, aes_iv, is_encryption);
    fwrite(out_buf, 1, sizeof(out_buf), fp_out);
  }

  fclose(fp_in);
  fclose(fp_out);
  return 0;
}

