#include <stdlib.h>
#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "util.hpp"

using namespace libsnark;
using namespace std;

int main(){
    typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    pb_variable<FieldT> stand;
    pb_variable<FieldT> score;
    pb_variable<FieldT> less;
    pb_variable<FieldT> leq;
    score.allocate(pb,"score");
    stand.allocate(pb,"stand");
    pb.val(stand) = 425;
    comparison_gadget<FieldT> cmp(pb, 10, stand, score, less, leq, "cmp");
    cmp.generate_r1cs_constraints();
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(less, 1, FieldT::one()));

    pb.val(score) = 501; // secret
    cmp.generate_r1cs_witness();


    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;

    const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk = keypair.vk;

    print_vk_to_file<default_r1cs_ppzksnark_pp>(vk, "../build/vk_data");
    print_proof_to_file<default_r1cs_ppzksnark_pp>(proof, "../build/proof_data");

    return 0;
}