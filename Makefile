CFLAGS += -I$(ERTS_INCLUDE_DIR)

# secp256k1 libraries
CFLAGS += -I c_src/secp256k1/include
CFLAGS += -fPIC

# LD
LDFLAGS += c_src/secp256k1/.libs/libsecp256k1.a -lgmp

CONFIG_OPTS = --enable-module-extrakeys --enable-module-schnorrsig --disable-benchmark --disable-tests --disable-fast-install --with-pic

priv/nif.so: c_src/nif.c c_src/random.h c_src/utils.h c_src/secp256k1/.libs/libsecp256k1.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ c_src/random.h c_src/utils.h c_src/nif.c $(LDFLAGS)

c_src/secp256k1/.libs/libsecp256k1.a: c_src/secp256k1/Makefile
	$(MAKE) -C c_src/secp256k1

c_src/secp256k1/Makefile: c_src/secp256k1/configure
	cd c_src/secp256k1 && ./configure $(CONFIG_OPTS)

c_src/secp256k1/configure: c_src/secp256k1/autogen.sh
	cd c_src/secp256k1 && ./autogen.sh

c_src/secp256k1/autogen.sh:
  git clone https://github.com/bitcoin-core/secp256k1 c_src/secp256k1

clean:
	$(MAKE) clean -C c_src/secp256k1
	@rm -f priv/nif.so
