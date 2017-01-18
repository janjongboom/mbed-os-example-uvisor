#ifndef KEY_DERIVE_H_
#define KEY_DERIVE_H_

#include "mbed.h"
#include "stdio.h"
#include "stdbool.h"
#include "stdint.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

#define PROFILE_PROTECTION_HASH_LEN 32
#define PROFILE_PROTECTION_PLEN 32
#define PROFILE_PROTECTION_WRAP_KEY_LEN 32

#define AKA_PROFILE_NO_ERROR 0
#define AKA_PROFILE_ERROR_IN_PROFILE_STRUCTURE 1
#define AKA_PROFILE_ERROR_ALGORITHM_NOT_SUPPORTED 2
#define AKA_PROFILE_ERROR_PARAMETER_SIZE_NOT_SUPPORTED 3
#define AKA_PROFILE_MAC_ERROR 4
#define AKA_PROFILE_ENCRYPTION_PADDING_ERROR 5
#define AKA_PROFILE_ERRONEOUS_DEVICE_ID 6
#define AKA_PROFILE_REVOCATION_ERROR 7
#define AKA_PROFILE_MEMORY_ALLOCATION_ERROR 8
#define AKA_PROFILE_NULL_POINTER_ERROR 8
#define AKA_PROFILE_ECC_ERROR 8

typedef struct {
  /* Device ID */
	uint8_t *dev_ID_p;
	uint32_t dev_ID_len;
  /* private key for the wrapping of symmetric keys */
	uint8_t *priv_key_p;
	uint32_t priv_key_len;
  /* counter for replay protection */
  uint8_t counter;
  /* encryption key of size PROFILE_PROTECTION_ENC_KEY_LEN */
	uint8_t *enc_key_p;
  /* MAC key of size PROFILE_PROTECTION_MAC_KEY_LEN */
	uint8_t *mac_key_p;
  /* Response MAC key of size PROFILE_PROTECTION_MAC_KEY_LEN */
	uint8_t *rmac_key_p;
  /* MAC chaining value of size PROFILE_PROTECTION_ENC_BLOCK_LEN */
	uint8_t *mac_cv_p;
} AKA_protection_ctx_t;

void PrintBuffer(uint8_t *buffer_p, uint32_t buffer_len)
{
	int i;

	for (i=0; i<buffer_len; i++) {
		printf("%02x", *(buffer_p + i));
		if ((i != 0)&&((i+1) % 4 == 0))
		{
			printf(" ");
		}
		if ((i != 0)&&((i+1) % 16 == 0))
		{
			printf("\r\n");
		}
	}
	printf("\r\n");
}

/*---------------------------------------------------------------------------*/
/*                         AKA_Profile_MGF1_SHA256()                         */
/*---------------------------------------------------------------------------*/
/**
 * This function generates a mask from a seed using the SHA-256 hash function.
 *
 * \param[in]     seed_p       Pointer to a buffer containing the seed of the mask
 * \param[in]     seed_len     Length of the seed buffer
 * \param[out]    mask_p       Pointer to a buffer where the mask will be stored
 * \param[out]    mask_len     Length of the buffer where the mask will be stored
 *
 */
/*---------------------------------------------------------------------------*/

void AKA_Profile_MGF1_SHA256(uint8_t *seed_p, uint32_t seed_len, uint8_t *mask_p, uint32_t mask_len)
{
  uint8_t hash[PROFILE_PROTECTION_HASH_LEN];
  uint8_t counter[4];
  uint8_t *p;
  size_t i, use_len;
  mbedtls_sha256_context ctx;

  memset(hash, 0, PROFILE_PROTECTION_HASH_LEN);
  memset(counter, 0, 4);

  p = mask_p;
  mbedtls_sha256_init(&ctx);

  while( mask_len > 0 )
  {
    use_len = PROFILE_PROTECTION_HASH_LEN;
    if(mask_len < PROFILE_PROTECTION_HASH_LEN)
      use_len = mask_len;
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, seed_p, seed_len);
    mbedtls_sha256_update(&ctx, counter, 4);
    mbedtls_sha256_finish(&ctx, hash);

    for( i = 0; i < use_len; ++i )
      *p++ = hash[i];
    counter[3]++;
    mask_len -= use_len;
  }
}

static void start_filling_up() {
    void* buffer;
    uint32_t allocated = 0;

    uint32_t size = 4096;

    while (true) {
        if (size == 64) break;

        buffer = malloc(size);
        if (buffer == NULL) {
            size = size / 2;
            continue;
        }
        printf("Allocated %d bytes\r\n", size);
        allocated += size;
        wait_ms(10);
    }
    printf("Allocated %d bytes before failed\r\n", allocated);
}

/*---------------------------------------------------------------------------*/
/*                     AKA_Profile_Derive_Wrapping_Key()                     */
/*---------------------------------------------------------------------------*/
/**
 * This function derives the wrapping key wrapped using PSEC-KEM mechanism
 * using the device public key. Derivation/unwrapping is done using the device
 * private key.
 *
 * \param[in]     buf_p          Pointer to buffer with the wrapped key
 * \param[in]     buf_len        Length of the buffer with the wrapped key
 * \param[in]     ctx            Pointer to the profile protection ctx
 * \param[out]    wrap_key_p     Pointer to buffer to store the wrapping key
 *
 * \return        0 for no error, non-zero value indicates errors
 */
/*---------------------------------------------------------------------------*/

uint32_t AKA_Profile_Derive_Wrapping_Key(uint8_t *buf_p, uint32_t buf_len,
                                 AKA_protection_ctx_t *ctx, uint8_t *wrap_key_p)
{

  printf("AKA_Profile_Derive_Wrapping_Key 1\r\n");

	uint32_t errcode = AKA_PROFILE_ERROR_IN_PROFILE_STRUCTURE;
  uint8_t random[PROFILE_PROTECTION_HASH_LEN];
  uint8_t *seed = NULL;
  uint8_t *h = NULL;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point C1, C1_exp, V;
  mbedtls_mpi d, alpha, tmp;
  int i;
  void* p;

  printf("AKA_Profile_Derive_Wrapping_Key 2\r\n");

  /* Check buffers are not NULL */
	if ((!buf_p) || (!ctx) || (!ctx->priv_key_p) || (!wrap_key_p)) {
    errcode = AKA_PROFILE_NULL_POINTER_ERROR;
		goto ERROR;
	}
  /* Check that input buffer is of correct length */
  if (buf_len != 1 + 2*PROFILE_PROTECTION_PLEN + PROFILE_PROTECTION_HASH_LEN)
		return errcode;

  /* Initialize variables such that all are initialized in case we end up with "goto ERROR" */
  mbedtls_ecp_group_init(&grp);
  printf("grp after initialization: %d bytes\r\n", sizeof(grp));
  // PrintBuffer((uint8_t*)&grp, sizeof(grp));
  mbedtls_mpi_init(&d);
  printf("d after initialization: %d bytes\r\n", sizeof(d));
  // PrintBuffer((uint8_t*)&d, sizeof(d));
  mbedtls_mpi_init(&alpha);
  printf("alpha after initialization: %d bytes\r\n", sizeof(alpha));
  // PrintBuffer((uint8_t*)&alpha, sizeof(alpha));
  mbedtls_mpi_init(&tmp);
  printf("tmp after initialization: %d bytes\r\n", sizeof(tmp));
  // PrintBuffer((uint8_t*)&tmp, sizeof(tmp));
  mbedtls_ecp_point_init(&C1);
  printf("C1 after initialization: %d bytes\r\n", sizeof(C1));
  // PrintBuffer((uint8_t*)&C1, sizeof(C1));
  mbedtls_ecp_point_init(&C1_exp);
  printf("C1_exp after initialization: %d bytes\r\n", sizeof(C1_exp));
  // PrintBuffer((uint8_t*)&C1_exp, sizeof(C1_exp));
  mbedtls_ecp_point_init(&V);
  printf("V after initialization: %d bytes\r\n", sizeof(V));
  // PrintBuffer((uint8_t*)&V, sizeof(V));

  /* Load ECC group and private key d */
  if((errcode = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) != 0) {
    printf("Error in mbedtls_ecp_group_load, %4.4x\r\n", errcode);
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }
  printf("grp after ECC group loaded: %d bytes\r\n", sizeof(grp));
  PrintBuffer((uint8_t*)&grp, sizeof(grp));
  if((errcode = mbedtls_mpi_read_binary(&d,ctx->priv_key_p,ctx->priv_key_len)) != 0 ) {
    printf("Error in mbedtls_mpi_read_binary, %4.4x\r\n", errcode);
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }
  printf("d after reading private key from buffer: %d bytes\r\n", sizeof(d));
  PrintBuffer((uint8_t*)&d, sizeof(d));

  /*
   * Compute C1 := OS2ECPP(g)
   * where
   *   c0 = g || c2, and where g and c2 are octet strings such that the octet length
   *   of c2 is hLen and octet length of g is 1+2*pLen (R=uncompressed form is used)
   */
  if((errcode = mbedtls_ecp_point_read_binary(&grp,&C1, buf_p,1 + 2*PROFILE_PROTECTION_PLEN)) != 0) {
    printf("Error in mbedtls_ecp_point_read_binary, %4.4x\r\n", errcode);
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }
  printf("C1 after reading ECC point from buffer: %d bytes\r\n", sizeof(C1));
  PrintBuffer((uint8_t*)&C1, sizeof(C1));

#ifndef FEATURE_UVISOR
  // So without uvisor we got ~170K of heap space. Fill it up, so we have an equal playing field.
  p = calloc(160000, 1);
  printf("calloc a lot %p\r\n", p);
#endif

  // === 1. Here I have plenty of space on the heap. 10.624 bytes if called here...
  // start_filling_up();

  /* Compute V := d * C1, where d is the private key */
  if((errcode = mbedtls_ecp_mul(&grp,&V,&d,&C1,NULL,NULL)) != 0) {
    printf("Error in mbedtls_ecp_mul, %4.4x\r\n", errcode);
    printf("V after mbedtls_ecp_mul: %d bytes\r\n", sizeof(V));

    // === 2. Here I cannot allocate anything on the heap anymore... Completely out of memory.
    // start_filling_up();

    PrintBuffer((uint8_t*)&V, sizeof(V));
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }
  printf("V after mbedtls_ecp_mul: %d bytes\r\n", sizeof(V));
  PrintBuffer((uint8_t*)&V, sizeof(V));

  /*
   * Set r := c2 XOR KDF( I2OSP(1,4) || g || PECP2OSP(V) , hLen)
   * where
   *   KDF = MGF1(SHA-256; hashLen = 32)
   *   I2OSP(1,4) is integer 1 represented as an octet string of length 4,
   *   PECP2OSP(V) is the ellictic curve point x-coordinate converted to string of size pLen
   */
  /* Prepare seed for KDF */
 	seed = (uint8_t *)calloc(5 + 3*PROFILE_PROTECTION_PLEN, sizeof(uint8_t));
  if (!seed) {
    printf("Error allocating memory for the seed in AKA_Profile_Derive_Wrapping_Key\r\n");
    errcode = AKA_PROFILE_MEMORY_ALLOCATION_ERROR;
    goto ERROR;
	}
  memset(seed, 0, 3);
  seed[3]=1;
  memcpy(&seed[4], buf_p, 1+2*PROFILE_PROTECTION_PLEN);
  /* Check if V is zero (or "at infinity") */
  if (mbedtls_ecp_is_zero(&V))
  	memset(&seed[5+2*PROFILE_PROTECTION_PLEN],0,PROFILE_PROTECTION_PLEN);
  else {
    if((errcode = mbedtls_mpi_write_binary(&V.X,&seed[5+2*PROFILE_PROTECTION_PLEN],PROFILE_PROTECTION_PLEN)) != 0) {
      printf("Error in mbedtls_mpi_write_binary, %4.4x\r\n", errcode);
      errcode = AKA_PROFILE_ECC_ERROR;
      goto ERROR;
    }
  }

  /* compute random */
  AKA_Profile_MGF1_SHA256(seed, 5 + 3*PROFILE_PROTECTION_PLEN, random, PROFILE_PROTECTION_HASH_LEN);
  for (i=0;i<PROFILE_PROTECTION_HASH_LEN;i++)
    random[i]^=buf_p[i + 1 + 2*PROFILE_PROTECTION_PLEN];
  free(seed);

  /* Set the first 4 bytes of seed to zero, and fill the rest of seed with r */
 	seed = (uint8_t *)calloc(4 + PROFILE_PROTECTION_HASH_LEN, sizeof(uint8_t));
  if (!seed) {
    printf("Error allocating memory for the seed in AKA_Profile_Derive_Wrapping_Key\r\n");
    errcode = AKA_PROFILE_MEMORY_ALLOCATION_ERROR;
    goto ERROR;
	}
  memset(seed, 0, 4);
  memcpy(&seed[4], random, PROFILE_PROTECTION_HASH_LEN);

  /*
   * Set h := KDF( I2OSP(0,4)|| r , pLen + 16 + keyLen)
   * where
   *   KDF = MGF1(SHA-256; hashLen = 32)
   *   I2OSP(0,4) is integer 0 represented as an octet string of length 4,
   *   pLen is the number of bytes to represent p = 32
   *   keyLen is the size of the AES key used to wrap the keys = 32
   */
  h = (uint8_t *)calloc(PROFILE_PROTECTION_PLEN + 16 + PROFILE_PROTECTION_WRAP_KEY_LEN, sizeof(uint8_t));
  if (!h) {
    printf("Error allocating memory for the mask in AKA_Profile_Derive_Wrapping_Key\r\n");
    errcode = AKA_PROFILE_MEMORY_ALLOCATION_ERROR;
    goto ERROR;
	}
  AKA_Profile_MGF1_SHA256(seed, 4 + PROFILE_PROTECTION_HASH_LEN, h, PROFILE_PROTECTION_PLEN + 16 + PROFILE_PROTECTION_WRAP_KEY_LEN);

  /* alpha is the pLen+16 first bytes of H seen as an integer modulo p (the order of P), data is copied from H to alpha */
  if((errcode = mbedtls_mpi_read_binary(&alpha,h,PROFILE_PROTECTION_PLEN + 16)) != 0) {
    printf("Error in mbedtls_mpi_read_binary, %4.4x\r\n", errcode);
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }
  if((errcode = mbedtls_mpi_mod_mpi(&tmp,&alpha,&grp.N)) != 0) {
    printf("Error in mbedtls_mpi_mod_mpi, %4.4x\r\n", errcode);
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }
  if((errcode = mbedtls_mpi_copy(&alpha,&tmp)) != 0) {
    printf("Error in mbedtls_mpi_copy, %4.4x\r\n", errcode);
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }

  /* Compute C1_exp := alpha * P, where P is the generator of the group (denoted G in mbedtls) */
  if((errcode = mbedtls_ecp_mul(&grp,&C1_exp,&alpha,&grp.G,NULL,NULL)) != 0) {
    printf("Error in mbedtls_ecp_mul, %4.4x\r\n", errcode);
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }

  /* Check that C1 equals C1_exp */
  if((errcode = mbedtls_ecp_point_cmp(&C1, &C1_exp)) != 0) {
    printf("Error C1 and C1_exp are not equal, %4.4x\r\n", errcode);
    errcode = AKA_PROFILE_ECC_ERROR;
    goto ERROR;
  }

  /* Copy the wrap key to the output buffer */
  memcpy(wrap_key_p, &h[PROFILE_PROTECTION_PLEN + 16], PROFILE_PROTECTION_WRAP_KEY_LEN);

  errcode = AKA_PROFILE_NO_ERROR;

ERROR:
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&C1);
  mbedtls_ecp_point_free(&C1_exp);
  mbedtls_ecp_point_free(&V);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&alpha);
  mbedtls_mpi_free(&tmp);
  free(h);
  free(seed);
  return errcode;
}

#endif // KEY_DERIVE_H_