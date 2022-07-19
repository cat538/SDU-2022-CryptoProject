pub mod comparison;

// TESTS
// ================================================================================================

#[cfg(test)]
pub fn test_example(example: Example, fail: bool) {
    let Example {
        program,
        inputs,
        pub_inputs,
        num_outputs,
        expected_result,
    } = example;

    let options = ProofOptions::new(
        32,
        8,
        0,
        miden::HashFunction::Blake3_256,
        miden::FieldExtension::None,
        8,
        256,
    );

    let (mut outputs, proof) = miden::execute(&program, &inputs, num_outputs, &options).unwrap();

    assert_eq!(
        expected_result, outputs,
        "Program result was computed incorrectly"
    );

    if fail {
        outputs[0] = outputs[0] + 1;
        assert!(miden::verify(*program.hash(), &pub_inputs, &outputs, proof).is_err())
    } else {
        assert!(miden::verify(*program.hash(), &pub_inputs, &outputs, proof).is_ok());
    }
}
