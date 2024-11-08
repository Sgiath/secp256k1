# C library source
LIB_URL = https://github.com/bitcoin-core/secp256k1
COMMIT_HASH = v0.6.0

# directories
TARGET_DIR := ./priv
SRC_DIR := ./c_src
LIB_SRC_DIR = $(SRC_DIR)/secp256k1

# Erlang headers
CFLAGS += -I$(ERTS_INCLUDE_DIR)

# secp256k1 libraries
CFLAGS += -I $(LIB_SRC_DIR)/include
CFLAGS += -fPIC -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes

# secp256k1 library options
CONFIG_OPTS = --disable-benchmark --disable-tests --disable-fast-install --with-pic

# utils
UTILS = $(SRC_DIR)/random.h $(SRC_DIR)/utils.h

# default target compile everything

.PHONY: all
all: $(TARGET_DIR)/ecdsa.so $(TARGET_DIR)/ecdh.so $(TARGET_DIR)/extrakeys.so $(TARGET_DIR)/schnorrsig.so

# NIFs compilation

$(TARGET_DIR)/%.so: $(SRC_DIR)/%.c $(UTILS) $(LIB_SRC_DIR)/.libs/libsecp256k1.a
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

# secp256k1 library compilation

$(LIB_SRC_DIR)/.libs/libsecp256k1.a: $(LIB_SRC_DIR)/Makefile
	$(MAKE) -C $(LIB_SRC_DIR)

$(LIB_SRC_DIR)/Makefile: $(LIB_SRC_DIR)/configure
	cd $(LIB_SRC_DIR) && ./configure $(CONFIG_OPTS)

$(LIB_SRC_DIR)/configure: $(LIB_SRC_DIR)/autogen.sh
	cd $(LIB_SRC_DIR) && ./autogen.sh

$(LIB_SRC_DIR)/autogen.sh:
	@rm -rf $(LIB_SRC_DIR)
	git clone --depth 1 --branch $(COMMIT_HASH) $(LIB_URL) $(LIB_SRC_DIR)

# cleaning

.PHONY: clean
clean:
	@rm -rf $(TARGET_DIR)
	@rm -rf $(LIB_SRC_DIR)
