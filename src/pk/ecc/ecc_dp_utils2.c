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

typedef struct {
   int size;                    /* The size of the curve in octets */
   void *prime;                 /* The prime that defines the field the curve is in */
   void *A;                     /* The fields A param */
   void *B;                     /* The fields B param */
   void *order;                 /* The order of the curve */
   void *Gx;                    /* The x co-ordinate of the base point on the curve */
   void *Gy;                    /* The y co-ordinate of the base point on the curve */
   unsigned long cofactor;      /* The co-factor */
   oid_st oid;                  /* The OID stucture */
} ltc_ecc_dp;

ltc_ecc_dp *ecc_dp_new_set(const ltc_ecc_set_type *set)
{
   ltc_ecc_dp *new;
   unsigned long i;
   int err;

   if (set == NULL || set->size == 0) return NULL;

   new = XMALLOC(sizeof(ltc_ecc_dp));
   if (new == NULL) return NULL;

   if ((err = mp_init_multi(&new->prime, &new->A, &new->B, &new->order, &new->Gx, &new->Gy, NULL)) != CRYPT_OK) {
      goto cleanup1;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_read_radix(new->A, set->A, 16)) != CRYPT_OK)           { goto cleanup2; }
   if ((err = mp_read_radix(new->B, set->B, 16)) != CRYPT_OK)           { goto cleanup2; }
   if ((err = mp_read_radix(new->order, set->order, 16)) != CRYPT_OK)   { goto cleanup2; }
   if ((err = mp_read_radix(new->prime, set->prime, 16)) != CRYPT_OK)   { goto cleanup2; }
   if ((err = mp_read_radix(new->Gx, set->Gx, 16)) != CRYPT_OK)         { goto cleanup2; }
   if ((err = mp_read_radix(new->Gy, set->Gy, 16)) != CRYPT_OK)         { goto cleanup2; }
   /* cofactor & size */
   new->cofactor = set->cofactor;
   new->size = set->size;
   /* OID */
   new->oid.OIDlen = set->oid.OIDlen;
   for (i = 0; i < new->oid.OIDlen; i++) new->oid.OID[i] = set->oid.OID[i];
   return new;

cleanup2:
   mp_clear_multi(new->prime, new->A, new->B, new->order, new->Gx, new->Gy, NULL);
cleanup1:
   XFREE(new);
   return NULL;
}

ltc_ecc_dp *ecc_dp_new_name(char *curve_name)
{
   int i;
   for (i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if (ltc_ecc_sets[i].name != NULL && XSTRCMP(ltc_ecc_sets[i].name, curve_name) == 0) {
         break;
      }
   }
   return ecc_dp_new_set(&ltc_ecc_sets[i]);
}

ltc_ecc_dp *ecc_dp_new_oid(unsigned long *oid, unsigned long oidsize)
{
   int i;
   for(i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if ((oidsize == ltc_ecc_sets[i].oid.OIDlen) &&
          (XMEM_NEQ(oid, ltc_ecc_sets[i].oid.OID, sizeof(unsigned long) * ltc_ecc_sets[i].oid.OIDlen) == 0)) {
         break;
      }
   }
   return ecc_dp_new_set(&ltc_ecc_sets[i]);
}

ltc_ecc_dp *ecc_dp_new_size(int size)
{
   /* for compatibility with libtomcrypt-1.17 the sizes below must match the specific curves */
   if (size <= 14) {
      return ecc_dp_new_name("SECP112R1");
   }
   else if (size <= 16) {
      return ecc_dp_new_name("SECP128R1");
   }
   else if (size <= 20) {
      return ecc_dp_new_name("SECP160R1");
   }
   else if (size <= 24) {
      return ecc_dp_new_name("SECP192R1");
   }
   else if (size <= 28) {
      return ecc_dp_new_name("SECP224R1");
   }
   else if (size <= 32) {
      return ecc_dp_new_name("SECP256R1");
   }
   else if (size <= 48) {
      return ecc_dp_new_name("SECP384R1");
   }
   else if (size <= 66) {
      return ecc_dp_new_name("SECP521R1");
   }
   return NULL;
}

void ecc_dp_free(ltc_ecc_dp *dp)
{
   if (dp == NULL) return;
   if (dp->prime != NULL) XFREE(dp->prime);
   if (dp->A     != NULL) XFREE(dp->A);
   if (dp->B     != NULL) XFREE(dp->B);
   if (dp->order != NULL) XFREE(dp->order);
   if (dp->Gx    != NULL) XFREE(dp->Gx);
   if (dp->Gy    != NULL) XFREE(dp->Gy);
   XFREE(dp);
   return;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
