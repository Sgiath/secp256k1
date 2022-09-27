defmodule Secp256k1.ECDH do
  @moduledoc false

  @on_load :load_nifs

  def load_nifs do
    :secp256k1
    |> Application.app_dir("priv/ecdh")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  @type shared_secret() :: <<_::32, _::_*8>>

  @spec ecdh(seckey :: Secp256k1.seckey(), pubkey :: Secp256k1.EC.compressed()) :: shared_secret()
  def ecdh(_seckey, _pubkey) do
    exit(:nif_not_loaded)
  end
end
