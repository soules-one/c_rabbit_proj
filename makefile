CC = clang
CFLAGS = -Wall -Wextra -O2 -fsanitize=address,undefined
PIC = -fPIC
BUILD_DIR = build

CLI32 = $(BUILD_DIR)/rabbit32
CLI64 = $(BUILD_DIR)/rabbit64
LIB32 = $(BUILD_DIR)/librabbit32.so
LIB64 = $(BUILD_DIR)/librabbit64.so

HOST_BITNESS := $(shell getconf LONG_BIT)

ifeq ($(HOST_BITNESS),32)
    DEFAULT_CLI = $(CLI32)
    DEFAULT_LIB = $(LIB32)
    DEFAULT_FLAGS = -m32 -DRABBIT_32BIT
else
    DEFAULT_CLI = $(CLI64)
    DEFAULT_LIB = $(LIB64)
    DEFAULT_FLAGS = -m64
endif

define run_tests_pipeline
	@echo "--- Testing target: $(1) ---"
	# rfc4503 test vectors check
	$(CC) $(CFLAGS) $(2) test.c rabbit.c -o $(BUILD_DIR)/test_vec_tmp
	$(BUILD_DIR)/test_vec_tmp
	@rm -f $(BUILD_DIR)/test_vec_tmp

	# generated key with iv
	$(1) -k $(BUILD_DIR)/test.key
	cat rabbit.h | $(1) -e $(BUILD_DIR)/test.key > $(BUILD_DIR)/enc_iv.bin
	cat $(BUILD_DIR)/enc_iv.bin | $(1) -d $(BUILD_DIR)/test.key > $(BUILD_DIR)/dec_iv.bin
	@cmp rabbit.h $(BUILD_DIR)/dec_iv.bin && echo "[ SUCCESS ] Fresh key + Random IV passed" || exit 1

	# generated key with no iv
	cat rabbit.h | $(1) -e -noiv $(BUILD_DIR)/test.key > $(BUILD_DIR)/enc_noiv.bin
	cat $(BUILD_DIR)/enc_noiv.bin | $(1) -d -noiv $(BUILD_DIR)/test.key > $(BUILD_DIR)/dec_noiv.bin
	@cmp rabbit.h $(BUILD_DIR)/dec_noiv.bin && echo "[ SUCCESS ] Fresh key + No IV passed" || exit 1

	# executable as a key with no iv
	cat rabbit.h | $(1) -e -noiv $(1) > $(BUILD_DIR)/enc_self.bin
	cat $(BUILD_DIR)/enc_self.bin | $(1) -d -noiv $(1) > $(BUILD_DIR)/dec_self.bin
	@cmp rabbit.h $(BUILD_DIR)/dec_self.bin && echo "[ SUCCESS ] Binary file as key passed\n" || exit 1
endef


# build util and lib for current system
make: $(BUILD_DIR) $(DEFAULT_CLI) $(DEFAULT_LIB)
	@echo "Built util and lib for ($(HOST_BITNESS)-bit) system."
	$(call run_tests_pipeline,$(DEFAULT_CLI),$(DEFAULT_FLAGS))

# build for all bitnesses
all: $(BUILD_DIR) $(CLI32) $(CLI64) $(LIB32) $(LIB64)
	@echo "Built util and lib for 32-bit and 64-bit systems."
	$(call run_tests_pipeline,$(CLI32),-m32 -DRABBIT_32BIT)
	$(call run_tests_pipeline,$(CLI64),-m64)

# built 32 bit util and cli
rabbit32: $(BUILD_DIR) $(CLI32) $(LIB32)
	$(call run_tests_pipeline,$(CLI32),-m32 -DRABBIT_32BIT)

# build 64 bit util and cli
rabbit64: $(BUILD_DIR) $(CLI64) $(LIB64)
	$(call run_tests_pipeline,$(CLI64),-m64)

profile: all
	@echo " PERFORMANCE PROFILING (32-bit vs 64-bit) "
	@echo "Generating 1000MB dummy data for throughput test..."
	@truncate -s 1000M $(BUILD_DIR)/large.bin
	@echo "\n>>> Timing 64-bit version:"
	@time $(CLI64) -e -noiv $(CLI64) < $(BUILD_DIR)/large.bin > /dev/null
	@echo "\n>>> Timing 32-bit version:"
	@time $(CLI32) -e -noiv $(CLI32) < $(BUILD_DIR)/large.bin > /dev/null
	@rm -f $(BUILD_DIR)/large.bin
	@echo "END OF TEST"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)


$(CLI32): main.c rabbit.c rabbit.h
	$(CC) $(CFLAGS) -m32 -DRABBIT_32BIT main.c rabbit.c -o $@

$(LIB32): rabbit.c rabbit.h
	$(CC) $(CFLAGS) -m32 -DRABBIT_32BIT $(PIC) -shared rabbit.c -o $@

$(CLI64): main.c rabbit.c rabbit.h
	$(CC) $(CFLAGS) -m64 main.c rabbit.c -o $@

$(LIB64): rabbit.c rabbit.h
	$(CC) $(CFLAGS) -m64 $(PIC) -shared rabbit.c -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: make all rabbit32 rabbit64 clean