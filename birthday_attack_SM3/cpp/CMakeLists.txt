project(test_openssl)
cmake_minimum_required(VERSION 3.13)
set(CMAKE_BUILD_TYPE "Debug")

message("-- CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}") 
set(CMAKE_TOOLCHAIN_FILE "D:/vcpkg/scripts/buildsystems/vcpkg.cmake")
find_package(OpenSSL)
add_executable(test source.cpp)
target_link_libraries(test OpenSSL::Crypto)
#target_compile_options(test "-")

