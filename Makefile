# C library source
LIB_URL = https://github.com/bitcoin-core/secp256k1
COMMIT_HASH = 694ce8fb2d1fd8a3d641d7c33705691d41a2a860
SRC_DIR = c_src/secp256k1

# Erlang headers
CFLAGS += -I$(ERTS_INCLUDE_DIR)

# secp256k1 libraries
CFLAGS += -I $(SRC_DIR)/include
CFLAGS += -fPIC

# LD
LDFLAGS += $(SRC_DIR)/.libs/libsecp256k1.a -lgmp

CONFIG_OPTS = --enable-module-extrakeys --enable-module-schnorrsig --disable-benchmark --disable-tests --disable-fast-install --with-pic

priv/nif.so: c_src/nif.c c_src/random.h c_src/utils.h $(SRC_DIR)/.libs/libsecp256k1.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ c_src/random.h c_src/utils.h c_src/nif.c $(LDFLAGS)

$(SRC_DIR)/.libs/libsecp256k1.a: $(SRC_DIR)/Makefile
	$(MAKE) -C $(SRC_DIR)

$(SRC_DIR)/Makefile: $(SRC_DIR)/configure
	cd $(SRC_DIR) && ./configure $(CONFIG_OPTS)

$(SRC_DIR)/configure: $(SRC_DIR)/autogen.sh
	cd $(SRC_DIR) && ./autogen.sh

$(SRC_DIR)/autogen.sh:
	@rm -rf $(SRC_DIR)
	git clone $(LIB_URL) $(SRC_DIR)
	cd $(SRC_DIR) && git checkout $(COMMIT_HASH)

clean:
	$(MAKE) clean -C $(SRC_DIR)
	@rm -f priv/nif.so
