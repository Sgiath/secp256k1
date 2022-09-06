CFLAGS += -I$(ERTS_INCLUDE_DIR)
LDFLAGS += -lgmp

MODULES = --enable-module-extrakeys --enable-module-schnorrsig

priv/nif.so: c_src/nif.c c_src/secp256k1/.libs/libsecp256k1.so
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ c_src/nif.c $(LDFLAGS)

c_src/secp256k1/.libs/libsecp256k1.so: c_src/secp256k1/include/secp256k1.h
	cd c_src/secp256k1 && ./autogen.sh
	cd c_src/secp256k1 && ./configure $(MODULES)
	$(MAKE) -C c_src/secp256k1

c_src/secp256k1/include/secp256k1.h:
	git submodule update --init --recursive
