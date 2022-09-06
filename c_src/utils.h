#include <erl_nif.h>

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
