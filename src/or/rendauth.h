#ifndef TOR_RENDAUTH_H
#define TOR_RENDAUTH_H

// Contains password based authorization info for hidden services in clear form.
struct rend_auth_password_t {
  char* username;
  size_t username_len;
  char* password;
  size_t password_len;
};

typedef struct{
	  uint8_t content;
} auth_keyid;

typedef struct{
	  uint8_t content;
} enc_keyid;

enum rend_auth_hash_method_t {
  REND_AUTH_HASH_SCRYPT_LOW = 0
};

int rend_auth_add_user (const char* filename, smartlist_t* new_users,
                        enum rend_auth_hash_method_t hash_method);

int verify_signature(const ed25519_signature_t *signature,
                            const ed25519_public_key_t *pubkey,
                            const uint8_t *msg);

int create_auth_signature(const ed25519_keypair_t *keypair,
                                 const auth_keyid *auth,
                                 const enc_keyid *enc,
                                 const ed25519_signature_t *sig);

#endif
