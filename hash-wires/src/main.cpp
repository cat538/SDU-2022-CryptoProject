#include "fmt/format.h"
#include "fmt/ranges.h"
#include "sodium.h"
#include "utils.h"
#include <chrono>

#include "tests.hpp"

using std::vector;
using std::string;

class Proof {
public:
	Proof() = delete;
	Proof(std::array<vector<uint8_t>, 3>& data, vector<uint8_t>& chksum) : data_(data), chksum_(chksum) {}

	void display();
private:
	std::array<vector<uint8_t>, 3> data_;
	vector<uint8_t> chksum_;
};

void Proof::display() {
	fmt::print("{:*^100}\n", "ROOT PROOF");
	fmt::print(">>>Data:\n");
	std::for_each(begin(data_), end(data_), [](const auto& v) {
		utils::print_hex(v.data(), v.size());
	});
	fmt::print(">>>Checksum:\n");
	utils::print_hex(chksum_.data(), chksum_.size());
}

void my_test() {
	tests::test_key_derivation();
	tests::test_crypto_hash();
	tests::test_crypto_seed();
	tests::test_crypto_kdf();
	tests::test_crypto_shuffle();
}

vector<uint8_t> pl_accum (std::array<vector<uint8_t>, 3> input) {
	input[0].insert(end(input[0]), begin(input[1]), end(input[1]));
	input[0].insert(end(input[0]), begin(input[2]), end(input[2]));
	return utils::crypto_hash(std::move(input[0]));
};

/**
 * @param	seed
 * 
 * seed:
 * - [seed_D] := KDF(seed)
 * - [s_1,s_2,s_3] := KDF(seed)
 * - [shuffle_seed,salt_A,salt_B,salt_C] := KDF(seed)
 * 
 * - comm_chksum := H^10(seed_D)
 * - a: comm_312 := PL-Accum(h^3(s_3),h^1(s_2),h^2(s_1))
 * - b: comm_303 := PL-Accum(h^3(s_3),h^0(s_2),h^3(s_1))
 * - c: comm_233 := PL-Accum(h^2(s_3),h^3(s_2),h^3(s_1))
 * 
 * - A: H(salt_A||a)
 * - B: H(salt_B||b)
 * - C: H(salt_C||c)
 * 
 * [x,y,z] := Shuffle([A,B,C], shuffle_seed)
 * Root := padded sparse Mtree([x,y,z,comm_chksum])
 * 
 * **/
auto hash_wires_sys(vector<uint8_t>&& seed) {
	static constexpr size_t kdf_num = 8;

	// ! TODO  这里不确定size大小，暂取全部32字节
	auto subkey_lens = vector<size_t>(kdf_num, 32);

	auto kdf_res = utils::crypto_kdf(std::move(seed), subkey_lens, "");

	vector<uint8_t> seed_d	= kdf_res[0];
	vector<uint8_t> s_1	= kdf_res[1];
	vector<uint8_t> s_2	= kdf_res[2];
	vector<uint8_t> s_3	= kdf_res[3];
	vector<uint8_t> sf_seed	= kdf_res[4];
	vector<uint8_t> salt_a	= kdf_res[5];
	vector<uint8_t> salt_b	= kdf_res[6];
	vector<uint8_t> salt_c	= kdf_res[7];


	auto h_11 = utils::crypto_hash(std::move(s_1));
	auto h_12 = utils::crypto_hash(std::move(h_11));
	auto h_12_copy = h_12;
	auto h_13 = utils::crypto_hash(std::move(h_12_copy));

	auto h_20 = s_2;
	auto h_21 = utils::crypto_hash(std::move(s_2));
	auto h_21_copy = h_21;
	auto h_22 = utils::crypto_hash(std::move(h_21_copy));
	auto h_23 = utils::crypto_hash(std::move(h_22));

	auto h_31 = utils::crypto_hash(std::move(s_3));
	auto h_32 = utils::crypto_hash(std::move(h_31));
	auto h_32_copy = h_32;
	auto h_33 = utils::crypto_hash(std::move(h_32_copy));

	
	// a, b, c
	auto comm_312 = pl_accum({ h_33, h_21, h_12 });
	auto comm_303 = pl_accum({ h_33, h_20, h_13 });
	auto comm_233 = pl_accum({ h_32, h_23, h_13 });

	comm_312.insert(end(comm_312), begin(salt_a), end(salt_a));
	comm_303.insert(end(comm_303), begin(salt_b), end(salt_b));
	comm_233.insert(end(comm_233), begin(salt_c), end(salt_c));
	auto x = utils::crypto_hash(std::move(comm_312));
	auto y = utils::crypto_hash(std::move(comm_303));
	auto z = utils::crypto_hash(std::move(comm_233));

	for (size_t i = 0; i < 10; i++) {
		auto tmp = std::move(seed_d);
		seed_d = utils::crypto_hash(std::move(tmp));
	}
	auto chksum = std::move(seed_d);

	// shuffle 这里细节不是特别清楚，留好了接口后续实现，目前只是取前64bit作为种子随机置换3个vector
	auto data = utils::crypto_shuffle({ x, y, z}, sf_seed);
	
	return Proof(data, chksum);
}

int main() {
	my_test();

	auto seed_main = utils::crypto_seed();

	auto t1 = std::chrono::steady_clock::now();
	auto proof = hash_wires_sys(std::move(seed_main));
	auto t2 = std::chrono::steady_clock::now();


	proof.display();
	fmt::print("\nTotal cost: {:3f} ms\n", std::chrono::duration<double, std::micro>(t2 - t1).count());
	return 0;
}

