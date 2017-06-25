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

ltc_ecc_set_type *ecc_dp_copy_set(const ltc_ecc_set_type *set)
{
   ltc_ecc_set_type *new;
   size_t len;
   unsigned long i;

   if (set == NULL || set->size == 0) return NULL;

   new = XMALLOC(sizeof(ltc_ecc_set_type));
   if (new == NULL) return NULL;

   /* A */
   len = strlen(set->A) + 1;
   if ((new->A = XMALLOC(len)) == NULL)                        goto cleanup1;
   strncpy(new->A, set->A, len);
   /* B */
   len = strlen(set->B) + 1;
   if ((new->B = XMALLOC(len)) == NULL)                        goto cleanup2;
   strncpy(new->B, set->B, len);
   /* order */
   len = strlen(set->order) + 1;
   if ((new->order = XMALLOC(len)) == NULL)                    goto cleanup3;
   strncpy(new->order, set->order, len);
   /* prime */
   len = strlen(set->prime) + 1;
   if ((new->prime = XMALLOC(len)) == NULL)                    goto cleanup4;
   strncpy(new->prime, set->prime, len);
   /* Gx */
   len = strlen(set->Gx) + 1;
   if ((new->Gx = XMALLOC(len)) == NULL)                       goto cleanup5;
   strncpy(new->Gx, set->Gx, len);
   /* Gy */
   len = strlen(set->Gy) + 1;
   if ((new->Gy = XMALLOC(len)) == NULL)                       goto cleanup6;
   strncpy(new->Gy, set->Gy, len);
   /* name */
   len = strlen(set->name) + 1;
   if ((new->name = XMALLOC(len)) == NULL)                     goto cleanup7;
   strncpy(new->name, set->name, len);
   /* cofactor & size */
   new->cofactor = set->cofactor;
   new->size = set->size;
   /* oid */
   new->oid.OIDlen = set->oid.OIDlen;
   for (i = 0; i < new->oid.OIDlen; i++) new->oid.OID[i] = set->oid.OID[i];
   return new;

cleanup7:
   XFREE(new->Gy);
cleanup6:
   XFREE(new->Gx);
cleanup5:
   XFREE(new->prime);
cleanup4:
   XFREE(new->order);
cleanup3:
   XFREE(new->B);
cleanup2:
   XFREE(new->A);
cleanup1:
   XFREE(new);
   return NULL;
}

ltc_ecc_set_type *ecc_dp_new_by_name(char *curve_name)
{
   int i;
   for (i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if (ltc_ecc_sets[i].name != NULL && XSTRCMP(ltc_ecc_sets[i].name, curve_name) == 0) {
         break;
      }
   }
   return ecc_dp_copy_set(&ltc_ecc_sets[i]);
}

ltc_ecc_set_type *ecc_dp_new_by_oid(unsigned long *oid, unsigned long oidsize)
{
   int i;
   for(i = 0; ltc_ecc_sets[i].size != 0; i++) {
      if ((oidsize == ltc_ecc_sets[i].oid.OIDlen) &&
          (XMEM_NEQ(oid, ltc_ecc_sets[i].oid.OID, sizeof(unsigned long) * ltc_ecc_sets[i].oid.OIDlen) == 0)) {
         break;
      }
   }
   return ecc_dp_copy_set(&ltc_ecc_sets[i]);
}

ltc_ecc_set_type *ecc_dp_new_by_size(int size)
{
   /* for compatibility with libtomcrypt-1.17 the sizes below must match the specific curves */
   if (size <= 14) {
      return ecc_dp_new_by_name("SECP112R1");
   }
   else if (size <= 16) {
      return ecc_dp_new_by_name("SECP128R1");
   }
   else if (size <= 20) {
      return ecc_dp_new_by_name("SECP160R1");
   }
   else if (size <= 24) {
      return ecc_dp_new_by_name("SECP192R1");
   }
   else if (size <= 28) {
      return ecc_dp_new_by_name("SECP224R1");
   }
   else if (size <= 32) {
      return ecc_dp_new_by_name("SECP256R1");
   }
   else if (size <= 48) {
      return ecc_dp_new_by_name("SECP384R1");
   }
   else if (size <= 66) {
      return ecc_dp_new_by_name("SECP521R1");
   }
   return NULL;
}

void ecc_dp_free(ltc_ecc_set_type *dp)
{
   if (dp == NULL) return;
   if (dp->name  != NULL) XFREE(dp->name);
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
