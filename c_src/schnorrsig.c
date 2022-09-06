#include "utils.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

// API

static ERL_NIF_TERM
sign32(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM result;
  ErlNifBinary message, seckey;

  secp256k1_keypair keypair;

  unsigned char auxiliary_rand[32];
  unsigned char signature[64];
  unsigned char *finished;

  /* load arguments given by Elixir */
  if (!enif_inspect_binary(env, argv[0], &message) ||
      !enif_inspect_binary(env, argv[1], &seckey))
  {
    return enif_make_badarg(env);
  }

  /* check expected arguments size */
  if (message.size != 32 || seckey.size != 32)
  {
    return enif_make_badarg(env);
  }

  /* create key pair from secret key */
  if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
  {
    return error_result(env, "secp256k1_keypair_create failed");
  }

  /* Generate 32 bytes of randomness to use with BIP-340 schnorr signing
   *
   * BIP-340 recommends passing 32 bytes of randomness to the signing function to improve
   * security against side-channel attacks */
  if (!fill_random(auxiliary_rand, sizeof(auxiliary_rand)))
  {
    return error_result(env, "Failed to generate randomness");
  }

  /* Generate a Schnorr signature */
  if (!secp256k1_schnorrsig_sign32(ctx, signature, message.data, &keypair, auxiliary_rand))
  {
    return error_result(env, "secp256k1_schnorrsig_sign32 failed");
  }

  /* Convert signature to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(signature), &result);
  memcpy(finished, signature, sizeof(signature));
  return ok_result(env, &result);
}

static ERL_NIF_TERM
sign_custom(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM result;
  ErlNifBinary message, seckey;

  secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
  secp256k1_keypair keypair;

  unsigned char auxiliary_rand[32];
  unsigned char signature[64];
  unsigned char *finished;

  /* load arguments given by Elixir */
  if (!enif_inspect_binary(env, argv[0], &message) ||
      !enif_inspect_binary(env, argv[1], &seckey))
  {
    return enif_make_badarg(env);
  }

  /* check expected arguments size */
  if (seckey.size != 32)
  {
    return enif_make_badarg(env);
  }

  /* create key pair from secret key */
  if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
  {
    return error_result(env, "secp256k1_keypair_create failed");
  }

  /* Generate 32 bytes of randomness to use with BIP-340 schnorr signing
   *
   * BIP-340 recommends passing 32 bytes of randomness to the signing function to improve
   * security against side-channel attacks */
  if (!fill_random(auxiliary_rand, sizeof(auxiliary_rand)))
  {
    return error_result(env, "Failed to generate randomness");
  }

  /* Assign the randomness to the extraparams data field */
  extraparams.ndata = &auxiliary_rand;

  /* Generate a Schnorr signature */
  if (!secp256k1_schnorrsig_sign_custom(ctx, signature, message.data, message.size, &keypair, &extraparams))
  {
    return error_result(env, "secp256k1_schnorrsig_sign_custom failed");
  }

  /* Convert signature to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(signature), &result);
  memcpy(finished, signature, sizeof(signature));
  return ok_result(env, &result);
}

static ERL_NIF_TERM
verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary signature, message, pubkey;

  secp256k1_xonly_pubkey xonly_pubkey;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &signature) ||
      !enif_inspect_binary(env, argv[1], &message) ||
      !enif_inspect_binary(env, argv[2], &pubkey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (signature.size != 64 || pubkey.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey, pubkey.data))
  {
    return error_result(env, "secp256k1_xonly_pubkey_parse failed");
  }

  if (secp256k1_schnorrsig_verify(ctx, signature.data, message.data, message.size, &xonly_pubkey))
  {
    return enif_make_atom(env, "valid");
  }

  return enif_make_atom(env, "invalid");
}

static ErlNifFunc nif_funcs[] = {
    {"sign32", 2, sign32},
    {"sign_custom", 2, sign_custom},
    {"verify", 3, verify},
};

ERL_NIF_INIT(Elixir.Secp256k1.Schnorr, nif_funcs, &load, NULL, &upgrade, &unload)
