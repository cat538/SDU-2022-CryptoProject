#pragma once

#include <array>
#include <vector>
#include <random>
#include <cstdint>
#include <algorithm>
#include "sodium.h"
#include "fmt/format.h"

using std::vector;
using std::string_view;

namespace utils {
	void print_hex(const uint8_t* data, uint64_t len) {
		for (size_t i = 0; i < len; i++) {
			fmt::print("{:02X}", data[i]);
		}
		fmt::print("\n");
	}

	/**
	 * @param	in
	 * @brief	Returns hash(in), Currently `SHA256` under the hood(后续考虑调整接口支持自定义hash function)
	 * **/
	vector<uint8_t> crypto_hash(vector<uint8_t>&& in) {
		static const size_t OUTPUT_SIZE = 32;
		static uint8_t buff[OUTPUT_SIZE]{};

		crypto_hash_sha256(buff, in.data(), in.size());
		return vector<uint8_t>(buff, buff + OUTPUT_SIZE);
	}

	vector<uint8_t> crypto_seed() {
		uint8_t rand_seed[crypto_kdf_KEYBYTES]{};
		crypto_kdf_keygen(rand_seed);

		return vector<uint8_t>(rand_seed, rand_seed + crypto_kdf_KEYBYTES);
	}

	vector<vector<uint8_t>> crypto_kdf(vector<uint8_t>&& master_key, const vector<size_t>& subkey_lens, const string_view& ctx) {
		vector<vector<uint8_t>> res{};
		uint64_t id = 1;
		for (const auto& len : subkey_lens) {
			auto subkey = vector<uint8_t>(len, 0);
			crypto_kdf_derive_from_key(subkey.data(), len, id++, ctx.data(), master_key.data());
			res.emplace_back(std::move(subkey));
		}
		return res;
	}

	std::array<vector<uint8_t>,3> crypto_shuffle(std::array<vector<uint8_t>,3>&& arr, vector<uint8_t> seed) {
		size_t seed_uint64 = *((uint64_t*)seed.data());
		std::mt19937 rng(seed_uint64);
		std::shuffle(arr.begin(), arr.end(), rng);
		return arr;
	}
}
