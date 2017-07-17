/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt.h"

#ifdef LTC_MECC

int ecc_set_dp(const ltc_ecc_set_type *set, ecc_key *key)
{
   unsigned long i;
   int err;

   LTC_ARGCHK(set != NULL);
   LTC_ARGCHK(set->size > 0);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_read_radix(key->dp.prime, set->prime, 16)) != CRYPT_OK) { goto error; }
   if ((err = mp_read_radix(key->dp.order, set->order, 16)) != CRYPT_OK) { goto error; }
   if ((err = mp_read_radix(key->dp.A, set->A, 16)) != CRYPT_OK)         { goto error; }
   if ((err = mp_read_radix(key->dp.B, set->B, 16)) != CRYPT_OK)         { goto error; }
   if ((err = mp_read_radix(key->dp.base.x, set->Gx, 16)) != CRYPT_OK)   { goto error; }
   if ((err = mp_read_radix(key->dp.base.y, set->Gy, 16)) != CRYPT_OK)   { goto error; }
   if ((err = mp_set(key->dp.base.z, 1)) != CRYPT_OK)                    { goto error; }
   /* cofactor & size */
   key->dp.cofactor = set->cofactor;
   key->dp.size = set->size;
   /* OID */
   key->dp.oid.OIDlen = set->oid.OIDlen;
   for (i = 0; i < key->dp.oid.OIDlen; i++) key->dp.oid.OID[i] = set->oid.OID[i];
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

int ecc_set_dp_name(char *curve_name, ecc_key *key)
{
   int i;
   for (i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if (ltc_ecc_sets[i].name != NULL && XSTRCMP(ltc_ecc_sets[i].name, curve_name) == 0) {
         break;
      }
   }
   return ecc_set_dp(&ltc_ecc_sets[i], key);
}

int ecc_set_dp_oid(unsigned long *oid, unsigned long oidsize, ecc_key *key)
{
   int i;
   for(i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if ((oidsize == ltc_ecc_sets[i].oid.OIDlen) &&
          (XMEM_NEQ(oid, ltc_ecc_sets[i].oid.OID, sizeof(unsigned long) * ltc_ecc_sets[i].oid.OIDlen) == 0)) {
         break;
      }
   }
   return ecc_set_dp(&ltc_ecc_sets[i], key);
}

int ecc_set_dp_size(int size, ecc_key *key)
{
   /* for compatibility with libtomcrypt-1.17 the sizes below must match the specific curves */
   if (size <= 14) {
      return ecc_set_dp_name("SECP112R1", key);
   }
   else if (size <= 16) {
      return ecc_set_dp_name("SECP128R1", key);
   }
   else if (size <= 20) {
      return ecc_set_dp_name("SECP160R1", key);
   }
   else if (size <= 24) {
      return ecc_set_dp_name("SECP192R1", key);
   }
   else if (size <= 28) {
      return ecc_set_dp_name("SECP224R1", key);
   }
   else if (size <= 32) {
      return ecc_set_dp_name("SECP256R1", key);
   }
   else if (size <= 48) {
      return ecc_set_dp_name("SECP384R1", key);
   }
   else if (size <= 66) {
      return ecc_set_dp_name("SECP521R1", key);
   }
   return CRYPT_INVALID_KEYSIZE;
}

int ecc_set_dp_copy(ecc_key *srckey, ecc_key *key)
{
   unsigned long i;
   int err;

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_copy(srckey->dp.prime,  key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.order,  key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.A,      key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.B,      key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.base.x, key->dp.base.x)) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.base.y, key->dp.base.y)) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.base.z, key->dp.base.z)) != CRYPT_OK) { goto error; }
   /* cofactor & size */
   key->dp.cofactor = srckey->dp.cofactor;
   key->dp.size     = srckey->dp.size;
   /* OID */
   key->dp.oid.OIDlen = srckey->dp.oid.OIDlen;
   for (i = 0; i < key->dp.oid.OIDlen; i++) key->dp.oid.OID[i] = srckey->dp.oid.OID[i];
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
