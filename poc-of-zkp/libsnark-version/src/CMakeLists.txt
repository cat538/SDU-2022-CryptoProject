include_directories(.)

add_executable(
  test

  test.cpp
)
target_link_libraries(
  test

  snark
)
target_include_directories(
  test

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(
  cet6

  cet6.cpp
)
target_link_libraries(
  cet6

  snark
)
target_include_directories(
  cet6

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test-gadget

  test-gadget.cpp
)
target_link_libraries(
  test-gadget

  snark
)
target_include_directories(
  test-gadget

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)