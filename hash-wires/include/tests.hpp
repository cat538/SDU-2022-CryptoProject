

namespace tests {
#include "utils.h"

	void test_key_derivation() {
		const std::string CONTEXT = "Examples";

		uint8_t master_key[crypto_kdf_KEYBYTES];
		uint8_t subkey1[32]{};
		uint8_t subkey2[32]{};
		uint8_t subkey3[64]{};

		crypto_kdf_keygen(master_key);

		// 注意这里子密钥：128..512 bits (即 16..64 bytes)
		crypto_kdf_derive_from_key(subkey1, sizeof subkey1, 1, CONTEXT.c_str(), master_key);
		crypto_kdf_derive_from_key(subkey2, sizeof subkey2, 2, CONTEXT.c_str(), master_key);
		crypto_kdf_derive_from_key(subkey3, sizeof subkey3, 3, CONTEXT.c_str(), master_key);

		fmt::print("{:=^100}\n", "TEST_KEY_DERIVATION");
		utils::print_hex(subkey1, 32);
		utils::print_hex(subkey2, 32);
		utils::print_hex(subkey3, 64);
	}

	void test_crypto_hash() {
		vector<uint8_t> input{ 1,2,3,4,5,6,7 };
		auto hash_res = utils::crypto_hash(std::move(input));

		fmt::print("{:=^100}\n", "TEST_CRYPTO_HASH");
		utils::print_hex(hash_res.data(), hash_res.size());
	}

	void test_crypto_seed() {
		auto seed = utils::crypto_seed();

		fmt::print("{:=^100}\n", "TEST_CRYPTO_SEED");
		utils::print_hex(seed.data(), seed.size());
	}

	void test_crypto_kdf() {
		auto seed = utils::crypto_seed();
		auto subkeys = utils::crypto_kdf(std::move(seed), { 32, 32,32,64 }, "nothing");

		fmt::print("{:=^100}\n", "TEST_CRYPTO_KDF");
		for (const auto& subkey : subkeys) {
			utils::print_hex(subkey.data(), subkey.size());
		}
	}

	void test_crypto_shuffle() {
		vector<uint8_t> arr1{ 1,2,3 };
		vector<uint8_t> arr2{ 4,5,6 };
		vector<uint8_t> arr3{ 7,8,9 };
		std::array<vector<uint8_t>, 3> vec{ arr1, arr2, arr3 };
		vector<uint8_t> seed{ 1,2,3 };
		auto res = utils::crypto_shuffle(std::move(vec), seed);
		fmt::print("{:=^100}\n", "TEST_CRYPTO_SHUFFLE");
		std::for_each(begin(res), end(res), [](const auto& v) {
			fmt::print("{}\n", v);
		});
	}
}