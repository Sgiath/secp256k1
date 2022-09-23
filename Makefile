# C library source
LIB_URL = https://github.com/bitcoin-core/secp256k1
COMMIT_HASH = 694ce8fb2d1fd8a3d641d7c33705691d41a2a860

# directories
TARGET_DIR := ./priv
SRC_DIR := ./c_src
LIB_SRC_DIR = $(SRC_DIR)/secp256k1

# Erlang headers
CFLAGS += -I$(ERTS_INCLUDE_DIR)

# secp256k1 libraries
CFLAGS += -I $(LIB_SRC_DIR)/include
CFLAGS += -fPIC

# LD
LDFLAGS += -lgmp

CONFIG_OPTS = --enable-module-ecdh --enable-module-extrakeys --enable-module-schnorrsig --disable-benchmark --disable-tests --disable-fast-install --with-pic

# utils
UTILS = $(SRC_DIR)/random.h $(SRC_DIR)/utils.h

# default target

.PHONY: all
all: $(TARGET_DIR)/ec.so $(TARGET_DIR)/ecdh.so $(TARGET_DIR)/extrakeys.so $(TARGET_DIR)/schnorrsig.so

# NIFs compilation

$(TARGET_DIR)/%.so: $(SRC_DIR)/%.c $(UTILS) $(LIB_SRC_DIR)/.libs/libsecp256k1.a
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

# secp256k1 library compilation

$(LIB_SRC_DIR)/.libs/libsecp256k1.a: $(LIB_SRC_DIR)/Makefile
	@$(MAKE) -C $(LIB_SRC_DIR)

$(LIB_SRC_DIR)/Makefile: $(LIB_SRC_DIR)/configure
	@cd $(LIB_SRC_DIR) && ./configure $(CONFIG_OPTS)

$(LIB_SRC_DIR)/configure: $(LIB_SRC_DIR)/autogen.sh
	@cd $(LIB_SRC_DIR) && ./autogen.sh

$(LIB_SRC_DIR)/autogen.sh:
	@rm -rf $(LIB_SRC_DIR)
	@git clone $(LIB_URL) $(LIB_SRC_DIR)
	@cd $(LIB_SRC_DIR) && git checkout $(COMMIT_HASH)

# cleaning

.PHONY: clean
clean:
	@rm -rf $(TARGET_DIR)
	@rm -rf $(LIB_SRC_DIR)
