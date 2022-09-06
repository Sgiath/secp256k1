#include <erl_nif.h>
#include <secp256k1.h>

#include "random.h"

static secp256k1_context *ctx = NULL;

static int
load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info)
{
  unsigned char randomize[32];
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  fill_random(randomize, sizeof(randomize));
  secp256k1_context_randomize(ctx, randomize);
  return 0;
}

static int
upgrade(ErlNifEnv *env, void **priv, void **old_priv, ERL_NIF_TERM load_info)
{
  return 0;
}

static void
unload(ErlNifEnv *env, void *priv)
{
  secp256k1_context_destroy(ctx);
  return;
}

static ERL_NIF_TERM
error_result(ErlNifEnv *env, char *error_msg)
{
  return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_string(env, error_msg, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM
ok_result(ErlNifEnv *env, ERL_NIF_TERM *r)
{
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), *r);
}
