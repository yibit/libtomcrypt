/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include <tomcrypt_test.h>

#ifdef LTC_MDSA

/* This is the private key from test_dsa.key */
static const unsigned char openssl_priv_dsa[] = {
  0x30, 0x82, 0x01, 0xbb, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xc5,
  0x0a, 0x37, 0x51, 0x5c, 0xab, 0xd6, 0x18, 0xd5, 0xa2, 0x70, 0xbd, 0x4a,
  0x6f, 0x6b, 0x4a, 0xf9, 0xe1, 0x39, 0x95, 0x0f, 0x2b, 0x99, 0x38, 0x7d,
  0x9a, 0x64, 0xd6, 0x4c, 0xb5, 0x96, 0x7a, 0xdc, 0xed, 0xac, 0xa8, 0xac,
  0xc6, 0x1b, 0x65, 0x5a, 0xde, 0xdb, 0x00, 0x61, 0x25, 0x1a, 0x18, 0x2c,
  0xee, 0xa1, 0x07, 0x90, 0x62, 0x5e, 0x4d, 0x12, 0x31, 0x90, 0xc7, 0x03,
  0x21, 0xfa, 0x09, 0xe7, 0xb1, 0x73, 0xd7, 0x8e, 0xaf, 0xdb, 0xfd, 0xbf,
  0xb3, 0xef, 0xad, 0xd1, 0xa1, 0x2a, 0x03, 0x6d, 0xe7, 0x06, 0x92, 0x4a,
  0x85, 0x2a, 0xff, 0x7a, 0x01, 0x66, 0x53, 0x1f, 0xea, 0xc6, 0x67, 0x41,
  0x84, 0x5a, 0xc0, 0x6c, 0xed, 0x62, 0xf9, 0xc2, 0x62, 0x62, 0x05, 0xa4,
  0xfa, 0x48, 0xa0, 0x66, 0xec, 0x35, 0xc9, 0xa8, 0x11, 0xfe, 0xb9, 0x81,
  0xab, 0xee, 0xbe, 0x31, 0xb6, 0xbf, 0xcf, 0x02, 0x15, 0x00, 0xaa, 0x5b,
  0xd7, 0xf4, 0xe5, 0x06, 0x24, 0x13, 0xe5, 0x88, 0x35, 0xca, 0x00, 0xc7,
  0xa6, 0x35, 0x71, 0x61, 0x94, 0xc5, 0x02, 0x81, 0x80, 0x3b, 0x92, 0xe4,
  0xff, 0x59, 0x29, 0x15, 0x0b, 0x08, 0x99, 0x5a, 0x7b, 0xf2, 0xad, 0x14,
  0x40, 0x55, 0x6f, 0xa0, 0x47, 0xff, 0x90, 0x99, 0xb3, 0x44, 0xb3, 0xd4,
  0xfc, 0x45, 0x15, 0x05, 0xae, 0x67, 0x22, 0x43, 0x9c, 0xba, 0x37, 0x10,
  0xa5, 0x89, 0x47, 0x37, 0xec, 0xcc, 0xf5, 0xae, 0xad, 0xa8, 0xb4, 0x7a,
  0x35, 0xcb, 0x9d, 0x93, 0x5c, 0xed, 0xe6, 0xb0, 0x7e, 0x96, 0x94, 0xc4,
  0xa6, 0x0c, 0x7d, 0xd6, 0x70, 0x8a, 0x09, 0x4f, 0x81, 0x4a, 0x0e, 0xc2,
  0x13, 0xfb, 0xeb, 0x16, 0xbf, 0xea, 0xa4, 0xf4, 0x56, 0xff, 0x72, 0x30,
  0x05, 0xde, 0x8a, 0x44, 0x3f, 0xbe, 0xc6, 0x85, 0x26, 0x55, 0xd6, 0x2d,
  0x1d, 0x1e, 0xdb, 0x15, 0xda, 0xa4, 0x45, 0x83, 0x3c, 0x17, 0x97, 0x98,
  0x0b, 0x8d, 0x87, 0xf3, 0x49, 0x0d, 0x90, 0xbd, 0xa9, 0xab, 0x67, 0x6e,
  0x87, 0x68, 0x72, 0x23, 0xdc, 0x02, 0x81, 0x80, 0x53, 0x16, 0xb0, 0xfb,
  0xbf, 0x59, 0x8a, 0x5e, 0x55, 0x95, 0xc1, 0x4f, 0xac, 0x43, 0xb8, 0x08,
  0x53, 0xe6, 0xcf, 0x0d, 0x92, 0x23, 0xfa, 0xb1, 0x84, 0x59, 0x52, 0x39,
  0xbf, 0xcb, 0xf2, 0x2d, 0x38, 0x3a, 0xdd, 0x93, 0x52, 0x05, 0x49, 0x7e,
  0x2b, 0x12, 0xc4, 0x61, 0x73, 0xe3, 0x6f, 0x54, 0xbd, 0x96, 0xe5, 0xa7,
  0xaa, 0xa9, 0x5a, 0x58, 0xa4, 0xb7, 0x67, 0xd2, 0xc0, 0xbd, 0xc8, 0x1e,
  0xb1, 0x3a, 0x12, 0x4f, 0x98, 0xc0, 0x05, 0xef, 0x39, 0x5d, 0x6a, 0xba,
  0xb7, 0x0b, 0x3b, 0xd8, 0xb7, 0x95, 0xdd, 0x79, 0x6e, 0xa2, 0xd2, 0x84,
  0x73, 0x47, 0x03, 0x88, 0xb4, 0x64, 0xd9, 0xb9, 0xb8, 0x4f, 0xf1, 0xc9,
  0x34, 0xbb, 0xf9, 0x73, 0x66, 0xf5, 0x7c, 0x2e, 0x11, 0xfe, 0xc3, 0x31,
  0xe6, 0x08, 0x38, 0x59, 0x67, 0x81, 0xeb, 0x6d, 0x41, 0x27, 0xd7, 0x0d,
  0x74, 0xaf, 0xa0, 0x35, 0x02, 0x15, 0x00, 0x99, 0x36, 0xe5, 0xe4, 0xe9,
  0xfb, 0x28, 0xbe, 0x91, 0xf5, 0x06, 0x5f, 0xe8, 0xc9, 0x35, 0xb3, 0xf5,
  0xd8, 0x1f, 0xc5
};

/* private key - raw hexadecimal numbers */
static char *hex_g = "3B92E4FF5929150B08995A7BF2AD1440556FA047FF9099B344B3D4FC451505AE6722439CBA3710A5894737ECCCF5AEADA8B47A35CB9D935CEDE6B07E9694C4A60C7DD6708A094F814A0EC213FBEB16BFEAA4F456FF723005DE8A443FBEC6852655D62D1D1EDB15DAA445833C1797980B8D87F3490D90BDA9AB676E87687223DC";
static char *hex_p = "C50A37515CABD618D5A270BD4A6F6B4AF9E139950F2B99387D9A64D64CB5967ADCEDACA8ACC61B655ADEDB0061251A182CEEA10790625E4D123190C70321FA09E7B173D78EAFDBFDBFB3EFADD1A12A036DE706924A852AFF7A0166531FEAC66741845AC06CED62F9C2626205A4FA48A066EC35C9A811FEB981ABEEBE31B6BFCF";
static char *hex_q = "AA5BD7F4E5062413E58835CA00C7A635716194C5";
static char *hex_x = "9936E5E4E9FB28BE91F5065FE8C935B3F5D81FC5";
static char *hex_y = "5316B0FBBF598A5E5595C14FAC43B80853E6CF0D9223FAB184595239BFCBF22D383ADD935205497E2B12C46173E36F54BD96E5A7AAA95A58A4B767D2C0BDC81EB13A124F98C005EF395D6ABAB70B3BD8B795DD796EA2D28473470388B464D9B9B84FF1C934BBF97366F57C2E11FEC331E60838596781EB6D4127D70D74AFA035";

/* The public part of test_dsa.key in SubjectPublicKeyInfo format */
static const unsigned char openssl_pub_dsa[] = {
  0x30, 0x82, 0x01, 0xb6, 0x30, 0x82, 0x01, 0x2b, 0x06, 0x07, 0x2a, 0x86,
  0x48, 0xce, 0x38, 0x04, 0x01, 0x30, 0x82, 0x01, 0x1e, 0x02, 0x81, 0x81,
  0x00, 0xc5, 0x0a, 0x37, 0x51, 0x5c, 0xab, 0xd6, 0x18, 0xd5, 0xa2, 0x70,
  0xbd, 0x4a, 0x6f, 0x6b, 0x4a, 0xf9, 0xe1, 0x39, 0x95, 0x0f, 0x2b, 0x99,
  0x38, 0x7d, 0x9a, 0x64, 0xd6, 0x4c, 0xb5, 0x96, 0x7a, 0xdc, 0xed, 0xac,
  0xa8, 0xac, 0xc6, 0x1b, 0x65, 0x5a, 0xde, 0xdb, 0x00, 0x61, 0x25, 0x1a,
  0x18, 0x2c, 0xee, 0xa1, 0x07, 0x90, 0x62, 0x5e, 0x4d, 0x12, 0x31, 0x90,
  0xc7, 0x03, 0x21, 0xfa, 0x09, 0xe7, 0xb1, 0x73, 0xd7, 0x8e, 0xaf, 0xdb,
  0xfd, 0xbf, 0xb3, 0xef, 0xad, 0xd1, 0xa1, 0x2a, 0x03, 0x6d, 0xe7, 0x06,
  0x92, 0x4a, 0x85, 0x2a, 0xff, 0x7a, 0x01, 0x66, 0x53, 0x1f, 0xea, 0xc6,
  0x67, 0x41, 0x84, 0x5a, 0xc0, 0x6c, 0xed, 0x62, 0xf9, 0xc2, 0x62, 0x62,
  0x05, 0xa4, 0xfa, 0x48, 0xa0, 0x66, 0xec, 0x35, 0xc9, 0xa8, 0x11, 0xfe,
  0xb9, 0x81, 0xab, 0xee, 0xbe, 0x31, 0xb6, 0xbf, 0xcf, 0x02, 0x15, 0x00,
  0xaa, 0x5b, 0xd7, 0xf4, 0xe5, 0x06, 0x24, 0x13, 0xe5, 0x88, 0x35, 0xca,
  0x00, 0xc7, 0xa6, 0x35, 0x71, 0x61, 0x94, 0xc5, 0x02, 0x81, 0x80, 0x3b,
  0x92, 0xe4, 0xff, 0x59, 0x29, 0x15, 0x0b, 0x08, 0x99, 0x5a, 0x7b, 0xf2,
  0xad, 0x14, 0x40, 0x55, 0x6f, 0xa0, 0x47, 0xff, 0x90, 0x99, 0xb3, 0x44,
  0xb3, 0xd4, 0xfc, 0x45, 0x15, 0x05, 0xae, 0x67, 0x22, 0x43, 0x9c, 0xba,
  0x37, 0x10, 0xa5, 0x89, 0x47, 0x37, 0xec, 0xcc, 0xf5, 0xae, 0xad, 0xa8,
  0xb4, 0x7a, 0x35, 0xcb, 0x9d, 0x93, 0x5c, 0xed, 0xe6, 0xb0, 0x7e, 0x96,
  0x94, 0xc4, 0xa6, 0x0c, 0x7d, 0xd6, 0x70, 0x8a, 0x09, 0x4f, 0x81, 0x4a,
  0x0e, 0xc2, 0x13, 0xfb, 0xeb, 0x16, 0xbf, 0xea, 0xa4, 0xf4, 0x56, 0xff,
  0x72, 0x30, 0x05, 0xde, 0x8a, 0x44, 0x3f, 0xbe, 0xc6, 0x85, 0x26, 0x55,
  0xd6, 0x2d, 0x1d, 0x1e, 0xdb, 0x15, 0xda, 0xa4, 0x45, 0x83, 0x3c, 0x17,
  0x97, 0x98, 0x0b, 0x8d, 0x87, 0xf3, 0x49, 0x0d, 0x90, 0xbd, 0xa9, 0xab,
  0x67, 0x6e, 0x87, 0x68, 0x72, 0x23, 0xdc, 0x03, 0x81, 0x84, 0x00, 0x02,
  0x81, 0x80, 0x53, 0x16, 0xb0, 0xfb, 0xbf, 0x59, 0x8a, 0x5e, 0x55, 0x95,
  0xc1, 0x4f, 0xac, 0x43, 0xb8, 0x08, 0x53, 0xe6, 0xcf, 0x0d, 0x92, 0x23,
  0xfa, 0xb1, 0x84, 0x59, 0x52, 0x39, 0xbf, 0xcb, 0xf2, 0x2d, 0x38, 0x3a,
  0xdd, 0x93, 0x52, 0x05, 0x49, 0x7e, 0x2b, 0x12, 0xc4, 0x61, 0x73, 0xe3,
  0x6f, 0x54, 0xbd, 0x96, 0xe5, 0xa7, 0xaa, 0xa9, 0x5a, 0x58, 0xa4, 0xb7,
  0x67, 0xd2, 0xc0, 0xbd, 0xc8, 0x1e, 0xb1, 0x3a, 0x12, 0x4f, 0x98, 0xc0,
  0x05, 0xef, 0x39, 0x5d, 0x6a, 0xba, 0xb7, 0x0b, 0x3b, 0xd8, 0xb7, 0x95,
  0xdd, 0x79, 0x6e, 0xa2, 0xd2, 0x84, 0x73, 0x47, 0x03, 0x88, 0xb4, 0x64,
  0xd9, 0xb9, 0xb8, 0x4f, 0xf1, 0xc9, 0x34, 0xbb, 0xf9, 0x73, 0x66, 0xf5,
  0x7c, 0x2e, 0x11, 0xfe, 0xc3, 0x31, 0xe6, 0x08, 0x38, 0x59, 0x67, 0x81,
  0xeb, 0x6d, 0x41, 0x27, 0xd7, 0x0d, 0x74, 0xaf, 0xa0, 0x35
};

static unsigned char dsaparam_der[] = {
   0x30, 0x82, 0x01, 0x1e, 0x02, 0x81, 0x81, 0x00, 0xc5, 0x0a, 0x37, 0x51,
   0x5c, 0xab, 0xd6, 0x18, 0xd5, 0xa2, 0x70, 0xbd, 0x4a, 0x6f, 0x6b, 0x4a,
   0xf9, 0xe1, 0x39, 0x95, 0x0f, 0x2b, 0x99, 0x38, 0x7d, 0x9a, 0x64, 0xd6,
   0x4c, 0xb5, 0x96, 0x7a, 0xdc, 0xed, 0xac, 0xa8, 0xac, 0xc6, 0x1b, 0x65,
   0x5a, 0xde, 0xdb, 0x00, 0x61, 0x25, 0x1a, 0x18, 0x2c, 0xee, 0xa1, 0x07,
   0x90, 0x62, 0x5e, 0x4d, 0x12, 0x31, 0x90, 0xc7, 0x03, 0x21, 0xfa, 0x09,
   0xe7, 0xb1, 0x73, 0xd7, 0x8e, 0xaf, 0xdb, 0xfd, 0xbf, 0xb3, 0xef, 0xad,
   0xd1, 0xa1, 0x2a, 0x03, 0x6d, 0xe7, 0x06, 0x92, 0x4a, 0x85, 0x2a, 0xff,
   0x7a, 0x01, 0x66, 0x53, 0x1f, 0xea, 0xc6, 0x67, 0x41, 0x84, 0x5a, 0xc0,
   0x6c, 0xed, 0x62, 0xf9, 0xc2, 0x62, 0x62, 0x05, 0xa4, 0xfa, 0x48, 0xa0,
   0x66, 0xec, 0x35, 0xc9, 0xa8, 0x11, 0xfe, 0xb9, 0x81, 0xab, 0xee, 0xbe,
   0x31, 0xb6, 0xbf, 0xcf, 0x02, 0x15, 0x00, 0xaa, 0x5b, 0xd7, 0xf4, 0xe5,
   0x06, 0x24, 0x13, 0xe5, 0x88, 0x35, 0xca, 0x00, 0xc7, 0xa6, 0x35, 0x71,
   0x61, 0x94, 0xc5, 0x02, 0x81, 0x80, 0x3b, 0x92, 0xe4, 0xff, 0x59, 0x29,
   0x15, 0x0b, 0x08, 0x99, 0x5a, 0x7b, 0xf2, 0xad, 0x14, 0x40, 0x55, 0x6f,
   0xa0, 0x47, 0xff, 0x90, 0x99, 0xb3, 0x44, 0xb3, 0xd4, 0xfc, 0x45, 0x15,
   0x05, 0xae, 0x67, 0x22, 0x43, 0x9c, 0xba, 0x37, 0x10, 0xa5, 0x89, 0x47,
   0x37, 0xec, 0xcc, 0xf5, 0xae, 0xad, 0xa8, 0xb4, 0x7a, 0x35, 0xcb, 0x9d,
   0x93, 0x5c, 0xed, 0xe6, 0xb0, 0x7e, 0x96, 0x94, 0xc4, 0xa6, 0x0c, 0x7d,
   0xd6, 0x70, 0x8a, 0x09, 0x4f, 0x81, 0x4a, 0x0e, 0xc2, 0x13, 0xfb, 0xeb,
   0x16, 0xbf, 0xea, 0xa4, 0xf4, 0x56, 0xff, 0x72, 0x30, 0x05, 0xde, 0x8a,
   0x44, 0x3f, 0xbe, 0xc6, 0x85, 0x26, 0x55, 0xd6, 0x2d, 0x1d, 0x1e, 0xdb,
   0x15, 0xda, 0xa4, 0x45, 0x83, 0x3c, 0x17, 0x97, 0x98, 0x0b, 0x8d, 0x87,
   0xf3, 0x49, 0x0d, 0x90, 0xbd, 0xa9, 0xab, 0x67, 0x6e, 0x87, 0x68, 0x72,
   0x23, 0xdc
 };


static int _dsa_compat_test(void)
{
  dsa_key key = LTC_DSA_KEY_INITIALIZER;
  unsigned char tmp[1024], buf[1024];
  unsigned long x, len;
  unsigned char key_parts[5][256];
  unsigned long key_lens[5];
  int stat;

  DO(dsa_import(openssl_priv_dsa, sizeof(openssl_priv_dsa), &key));

  x = sizeof(tmp);
  DO(dsa_export(tmp, &x, PK_PRIVATE | PK_STD, &key));
  if (compare_testvector(tmp, x, openssl_priv_dsa, sizeof(openssl_priv_dsa),
                         "DSA private export failed from dsa_import(priv_key)\n", 0)) {
     return CRYPT_FAIL_TESTVECTOR;
  }

  x = sizeof(tmp);
  DO(dsa_export(tmp, &x, PK_PUBLIC | PK_STD, &key));
  if (compare_testvector(tmp, x, openssl_pub_dsa, sizeof(openssl_pub_dsa),
                         "DSA public export failed from dsa_import(priv_key)\n", 0)) {
     return CRYPT_FAIL_TESTVECTOR;
  }
  dsa_free(&key);

  DO(dsa_import(openssl_pub_dsa, sizeof(openssl_pub_dsa), &key));

  x = sizeof(tmp);
  DO(dsa_export(tmp, &x, PK_PUBLIC | PK_STD, &key));
  if (compare_testvector(tmp, x, openssl_pub_dsa, sizeof(openssl_pub_dsa),
                         "DSA public export failed from dsa_import(pub_key)\n", 0)) {
     return CRYPT_FAIL_TESTVECTOR;
  }
  dsa_free(&key);

  /* try import private key from raw hexadecimal numbers */
  for (x = 0; x < 5; ++x) {
     key_lens[x] = sizeof(key_parts[x]);
  }
  DO(radix_to_bin(hex_p, 16, key_parts[0], &key_lens[0]));
  DO(radix_to_bin(hex_q, 16, key_parts[1], &key_lens[1]));
  DO(radix_to_bin(hex_g, 16, key_parts[2], &key_lens[2]));
  DO(radix_to_bin(hex_y, 16, key_parts[3], &key_lens[3]));
  DO(radix_to_bin(hex_x, 16, key_parts[4], &key_lens[4]));

  DO(dsa_set_pqg(key_parts[0], key_lens[0],
                 key_parts[1], key_lens[1],
                 key_parts[2], key_lens[2],
                 &key));
  DO(dsa_set_key(key_parts[3], key_lens[3],
                 key_parts[4], key_lens[4],
                 &key));
  len = sizeof(buf);
  DO(dsa_export(buf, &len, PK_PRIVATE | PK_STD, &key));
  if (compare_testvector(buf, len, openssl_priv_dsa, sizeof(openssl_priv_dsa),
                         "DSA private export failed from dsa_set_pqg() & dsa_set_key()\n", 0)) {
     return CRYPT_FAIL_TESTVECTOR;
  }
  dsa_free(&key);

  /* try import public key from raw hexadecimal numbers */
  DO(dsa_set_pqg(key_parts[0], key_lens[0],
                 key_parts[1], key_lens[1],
                 key_parts[2], key_lens[2],
                 &key));
  DO(dsa_set_key(key_parts[3], key_lens[3],
                 NULL, 0,
                 &key));
  len = sizeof(buf);
  DO(dsa_export(buf, &len, PK_PUBLIC | PK_STD, &key));
  if (compare_testvector(buf, len, openssl_pub_dsa, sizeof(openssl_pub_dsa),
                         "DSA public export failed from dsa_set_pqg() & dsa_set_key()\n", 0)) {
     return CRYPT_FAIL_TESTVECTOR;
  }
  dsa_free(&key);

  /* try import dsaparam */
  DO(dsa_set_pqg_dsaparam(dsaparam_der, sizeof(dsaparam_der), &key));
  DO(dsa_make_key_ex(&yarrow_prng, find_prng("yarrow"), &key));
  /* verify it */
  DO(dsa_verify_key(&key, &stat));
  if (stat == 0) {
     fprintf(stderr, "dsa_verify_key after dsa_set_pqg_dsaparam()");
     return CRYPT_FAIL_TESTVECTOR;
  }
  dsa_free(&key);

  /* try import dsaparam - our public key */
  DO(dsa_set_pqg_dsaparam(dsaparam_der, sizeof(dsaparam_der), &key));
  DO(dsa_set_key(key_parts[3], key_lens[3],
                 NULL, 0,
                 &key));
  len = sizeof(buf);
  DO(dsa_export(buf, &len, PK_PUBLIC | PK_STD, &key));
  if (compare_testvector(buf, len, openssl_pub_dsa, sizeof(openssl_pub_dsa),
                         "DSA public export failed from dsa_set_pqg_dsaparam()\n", 0)) {
     return CRYPT_FAIL_TESTVECTOR;
  }
  dsa_free(&key);

  /* try import dsaparam - our private key */
  DO(dsa_set_pqg_dsaparam(dsaparam_der, sizeof(dsaparam_der), &key));
  DO(dsa_set_key(key_parts[3], key_lens[3],
                 key_parts[4], key_lens[4],
                 &key));
  len = sizeof(buf);
  DO(dsa_export(buf, &len, PK_PRIVATE | PK_STD, &key));
  if (compare_testvector(buf, len, openssl_priv_dsa, sizeof(openssl_priv_dsa),
                         "DSA private export failed from dsa_set_pqg_dsaparam()\n", 0)) {
     return CRYPT_FAIL_TESTVECTOR;
  }
  dsa_free(&key);

  return CRYPT_OK;
}

int dsa_test(void)
{
   unsigned char msg[16], out[1024], out2[1024], ch;
   unsigned long x, y;
   int stat1, stat2;
   dsa_key key = LTC_DSA_KEY_INITIALIZER;
   dsa_key key2 = LTC_DSA_KEY_INITIALIZER;

   DO(_dsa_compat_test());

   /* make a random key */
   DO(dsa_generate_pqg(&yarrow_prng, find_prng("yarrow"), 20, 128, &key));
   DO(dsa_make_key_ex(&yarrow_prng, find_prng("yarrow"), &key));

   /* verify it */
   DO(dsa_verify_key(&key, &stat1));
   if (stat1 == 0) { fprintf(stderr, "dsa_verify_key "); return 1; }

   /* encrypt a message */
   for (ch = 0; ch < 16; ch++) { msg[ch] = ch; }
   x = sizeof(out);
   DO(dsa_encrypt_key(msg, 16, out, &x, &yarrow_prng, find_prng("yarrow"), find_hash("sha1"), &key));

   /* decrypt */
   y = sizeof(out2);
   DO(dsa_decrypt_key(out, x, out2, &y, &key));

   if (y != 16 || memcmp(out2, msg, 16)) {
      fprintf(stderr, "dsa_decrypt failed, y == %lu\n", y);
      return 1;
   }

   /* sign the message */
   x = sizeof(out);
   DO(dsa_sign_hash(msg, sizeof(msg), out, &x, &yarrow_prng, find_prng("yarrow"), &key));

   /* verify it once */
   DO(dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key));

   /* Modify and verify again */
   msg[0] ^= 1;
   DO(dsa_verify_hash(out, x, msg, sizeof(msg), &stat2, &key));
   msg[0] ^= 1;
   if (!(stat1 == 1 && stat2 == 0)) { fprintf(stderr, "dsa_verify %d %d", stat1, stat2); return 1; }

   /* test exporting it */
   x = sizeof(out2);
   DO(dsa_export(out2, &x, PK_PRIVATE, &key));
   DO(dsa_import(out2, x, &key2));

   /* verify a signature with it */
   DO(dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key2));
   if (stat1 == 0) { fprintf(stderr, "dsa_verify (import private) %d ", stat1); return 1; }
   dsa_free(&key2);

   /* export as public now */
   x = sizeof(out2);
   DO(dsa_export(out2, &x, PK_PUBLIC, &key));

   DO(dsa_import(out2, x, &key2));
   /* verify a signature with it */
   DO(dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key2));
   if (stat1 == 0) { fprintf(stderr, "dsa_verify (import public) %d ", stat1); return 1; }
   dsa_free(&key2);
   dsa_free(&key);

   return 0;
}

#else

int dsa_test(void)
{
  return CRYPT_NOP;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
