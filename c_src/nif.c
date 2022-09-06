#include "random.h"
#include "utils.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

static secp256k1_context *ctx = NULL;

// Global setup
static int
load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info)
{
  unsigned char randomize[32];
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  getrandom(randomize, sizeof(randomize), 0);
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

// API

static ERL_NIF_TERM
sign32(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM r;
  ErlNifBinary message, priv_key;

  secp256k1_xonly_pubkey xonly_pubkey;
  secp256k1_keypair keypair;

  unsigned char auxiliary_rand[32];
  unsigned char signature[64];
  unsigned char serialized_pubkey[32];
  unsigned char *finishedsig;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &message) ||
      !enif_inspect_binary(env, argv[1], &priv_key))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (message.size != 32 || priv_key.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_keypair_create(ctx, &keypair, priv_key.data))
  {
    return error_result(env, "secp256k1_keypair_create failed");
  }

  if (!fill_random(auxiliary_rand, sizeof(auxiliary_rand)))
  {
    return error_result(env, "Failed to generate randomness");
  }

  if (!secp256k1_schnorrsig_sign32(ctx, signature, message.data, &keypair, auxiliary_rand))
  {
    return error_result(env, "secp256k1_schnorrsig_sign32 failed");
  }

  finishedsig = enif_make_new_binary(env, sizeof(signature), &r);
  memcpy(finishedsig, signature, sizeof(signature));
  return ok_result(env, &r);
}

static ERL_NIF_TERM
sign_custom(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM r;
  ErlNifBinary message, priv_key;

  secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
  secp256k1_xonly_pubkey xonly_pubkey;
  secp256k1_keypair keypair;

  unsigned char auxiliary_rand[32];
  unsigned char signature[64];
  unsigned char serialized_pubkey[32];
  unsigned char *finishedsig;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &message) ||
      !enif_inspect_binary(env, argv[1], &priv_key))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (priv_key.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_keypair_create(ctx, &keypair, priv_key.data))
  {
    return error_result(env, "secp256k1_keypair_create failed");
  }

  if (!fill_random(extraparams.ndata, 32))
  {
    return error_result(env, "Failed to generate randomness");
  }

  if (!secp256k1_schnorrsig_sign_custom(ctx, signature, message.data, message.size, &keypair, &extraparams))
  {
    return error_result(env, "secp256k1_schnorrsig_sign_custom failed");
  }

  finishedsig = enif_make_new_binary(env, sizeof(signature), &r);
  memcpy(finishedsig, signature, sizeof(signature));
  return ok_result(env, &r);
}

static ERL_NIF_TERM
verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM r;
  ErlNifBinary message, signature, pubkey;

  secp256k1_xonly_pubkey xonly_pubkey;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &signature) ||
      !enif_inspect_binary(env, argv[1], &message) ||
      !enif_inspect_binary(env, argv[2], &pubkey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (signature.size != 64 || message.size != 32 || pubkey.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, pubkey.data))
  {
    return error_result(env, "secp256k1_xonly_pubkey_parse failed");
  }

  if (secp256k1_schnorrsig_verify(ctx, signature.data, message.data, 32, &xonly_pubkey))
  {
    return enif_make_atom(env, "valid");
  }

  return enif_make_atom(env, "invalid");
}

static ERL_NIF_TERM
xonly_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM r;
  ErlNifBinary priv_key;

  secp256k1_xonly_pubkey pubkey;
  secp256k1_keypair keypair;

  unsigned char serialized_pubkey[32];
  unsigned char *finishedsig;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &priv_key))
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_keypair_create(ctx, &keypair, priv_key.data))
  {
    return error_result(env, "secp256k1_keypair_create failed");
  }

  if (!secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair))
  {
    return error_result(env, "secp256k1_keypair_xonly_pub failed");
  }

  if (!secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey))
  {
    return error_result(env, "secp256k1_xonly_pubkey_serialize failed");
  }

  finishedsig = enif_make_new_binary(env, sizeof(serialized_pubkey), &r);
  memcpy(finishedsig, serialized_pubkey, sizeof(serialized_pubkey));
  return ok_result(env, &r);
}

static ErlNifFunc nif_funcs[] = {
    {"sign32", 2, sign32},
    {"sign_custom", 2, sign_custom},
    {"verify", 3, verify},
    {"xonly_pubkey", 1, xonly_pubkey},
};

ERL_NIF_INIT(Elixir.Secp256k1.Schnorr, nif_funcs, &load, NULL, &upgrade, &unload)
