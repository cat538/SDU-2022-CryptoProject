use log::debug;
use miden::{assembly, ProgramInputs};
use miden::{Program, ProofOptions};
use structopt::StructOpt;


// EXAMPLE
// ================================================================================================

pub struct Example {
    pub program: Program,
    pub inputs: ProgramInputs,
    pub pub_inputs: Vec<u128>,
    pub num_outputs: usize,
    pub expected_result: Vec<u128>,
}

// EXAMPLE OPTIONS
// ================================================================================================

#[derive(StructOpt, Debug)]
#[structopt(name = "Miden", about = "Miden examples")]
pub struct ExampleOptions {
    #[structopt(subcommand)]
    pub example: ExampleType,

    /// Security level for execution proofs generated by the VM
    #[structopt(short = "s", long = "security", default_value = "96bits")]
    security: String,
}

impl ExampleOptions {
    pub fn get_proof_options(&self) -> ProofOptions {
        match self.security.as_str() {
            "96bits" => ProofOptions::with_96_bit_security(),
            "128bits" => ProofOptions::with_128_bit_security(),
            other => panic!("{} is not a valid security level", other),
        }
    }
}

#[derive(StructOpt, Debug)]
//#[structopt(about = "available examples")]
pub enum ExampleType {
    /// Compute a Fibonacci sequence of the specified length
    Comparison {
        /// Value to compare to 9
        #[structopt(short = "n", default_value = "11")]
        value: usize,
    },
}



// EXAMPLE BUILDER
// ================================================================================================

pub fn get_example(value: usize) -> Example {
    // determine the expected result
    let value = value as u128;
    let expected_result = if value < 426 {  0 } else { 1  };

    // 比较六级成绩是否大于425的电路 
    let program = assembly::compile(
        "
    begin
        push.426
        read
        dup.2
        lt.128
        if.true
            push.0
        else
            push.1
        end
    end",
    )
    .unwrap();

    debug!(
        "Generated a program to test comparisons; expected result: {}",
        expected_result
    );

    Example {
        program,
        inputs: ProgramInputs::new(&[], &[value], &[]),
        pub_inputs: vec![],
        expected_result: vec![expected_result],
        num_outputs: 1,
    }
}

// EXAMPLE TESTER
// ================================================================================================

#[test]
fn test_comparison_example() {
    let example = get_example(10);
    super::test_example(example, false);
}

#[test]
fn test_comparison_example_fail() {
    let example = get_example(2);
    super::test_example(example, true);
}
