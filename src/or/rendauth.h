#ifndef TOR_RENDAUTH_H
#define TOR_RENDAUTH_H

// Contains password based authorization info for hidden services in clear form.
struct rend_auth_password_t {
  char* username;
  size_t username_len;
  char* password;
  size_t password_len;
};

enum rend_auth_hash_method_t {
  REND_AUTH_HASH_SCRYPT_LOW = 0
};

int rend_auth_add_user (const char* filename, smartlist_t* new_users,
                        enum rend_auth_hash_method_t hash_method);


#endif
