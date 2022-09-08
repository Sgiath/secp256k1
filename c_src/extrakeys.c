#include "utils.h"

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

// API

static ERL_NIF_TERM
xonly_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM result;
  ErlNifBinary seckey;

  secp256k1_xonly_pubkey pubkey;
  secp256k1_keypair keypair;

  unsigned char serialized_pubkey[32];
  unsigned char *finished;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &seckey))
  {
    return enif_make_badarg(env);
  }

  // check arguments size
  if (seckey.size != 32)
  {
    return enif_make_badarg(env);
  }

  if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
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

  /* Convert serialized pubkey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(serialized_pubkey), &result);
  memcpy(finished, serialized_pubkey, sizeof(serialized_pubkey));
  return ok_result(env, &result);
}

static int
is_prefix(unsigned char *data, unsigned char *prefix, size_t prefix_len)
{
  for (size_t i = 0; i < prefix_len; i++)
  {
    if (data[i] != prefix[i])
    {
      return 1;
    }
  }
  return 0;
}

static ERL_NIF_TERM
mine_seckey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  ERL_NIF_TERM result;
  ErlNifBinary prefix;

  secp256k1_xonly_pubkey pubkey;
  secp256k1_keypair keypair;

  unsigned char seckey[32];
  unsigned char serialized_pubkey[32];
  unsigned char *finished;

  // load arguments
  if (!enif_inspect_binary(env, argv[0], &prefix))
  {
    return enif_make_badarg(env);
  }

  do
  {
    fill_random(seckey, sizeof(seckey));
    secp256k1_keypair_create(ctx, &keypair, seckey);
    secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair);
    secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey);
  } while (is_prefix(serialized_pubkey, prefix.data, prefix.size) == 1);

  /* Convert seckey to Erlang binary */
  finished = enif_make_new_binary(env, sizeof(seckey), &result);
  memcpy(finished, seckey, sizeof(seckey));
  return ok_result(env, &result);
}

static ErlNifFunc nif_funcs[] = {
    {"xonly_pubkey", 1, xonly_pubkey},
    {"mine_seckey", 1, mine_seckey},
};

ERL_NIF_INIT(Elixir.Secp256k1.Extrakeys, nif_funcs, &load, NULL, &upgrade, &unload)
