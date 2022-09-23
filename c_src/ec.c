#include "utils.h"

// API

static ERL_NIF_TERM
compressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM result;
  ErlNifBinary seckey;

  secp256k1_pubkey pubkey;

  unsigned char serialized_pubkey[33];
  unsigned char *finished;
  size_t len;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &seckey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (!(seckey.size == 32 && secp256k1_ec_seckey_verify(ctx, seckey.data)))
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey.data))
  {
    return error_result(env, "secp256k1_ec_pubkey_create failed");
  }

  len = sizeof(serialized_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return result;
}

static ERL_NIF_TERM
uncompressed_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM result;
  ErlNifBinary seckey;

  secp256k1_pubkey pubkey;

  unsigned char serialized_pubkey[65];
  unsigned char *finished;
  size_t len;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &seckey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (!(seckey.size == 32 && secp256k1_ec_seckey_verify(ctx, seckey.data)))
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey.data))
  {
    return error_result(env, "secp256k1_ec_pubkey_create failed");
  }

  len = sizeof(serialized_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return result;
}

static ERL_NIF_TERM
compress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM result;
  ErlNifBinary input;

  secp256k1_pubkey pubkey;

  unsigned char serialized_pubkey[33];
  unsigned char *finished;
  size_t len;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &input))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (input.size != 65)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input.data, input.size))
  {
    return error_result(env, "secp256k1_ec_pubkey_parse failed");
  }

  len = sizeof(serialized_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return result;
}

static ERL_NIF_TERM
decompress_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM result;
  ErlNifBinary input;

  secp256k1_pubkey pubkey;

  unsigned char serialized_pubkey[65];
  unsigned char *finished;
  size_t len;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &input))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (input.size != 33)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input.data, input.size))
  {
    return error_result(env, "secp256k1_ec_pubkey_parse failed");
  }

  len = sizeof(serialized_pubkey);
  if (!secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED))
  {
    return error_result(env, "secp256k1_ec_pubkey_serialize failed");
  }

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return result;
}

static ErlNifFunc nif_funcs[] = {
    {"compressed_pubkey", 1, compressed_pubkey},
    {"uncompressed_pubkey", 1, uncompressed_pubkey},
    {"compress_pubkey", 1, compress_pubkey},
    {"decompress_pubkey", 1, decompress_pubkey},
};

ERL_NIF_INIT(Elixir.Secp256k1.EC, nif_funcs, &load, NULL, &upgrade, &unload)
