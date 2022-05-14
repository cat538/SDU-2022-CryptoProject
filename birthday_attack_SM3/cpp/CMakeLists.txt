cmake_minimum_required(VERSION 3.0)
project(sm3_attack)
set(CMAKE_BUILD_TYPE "Release")
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_executable(sm3_attack sm3_attack.cpp)
target_link_libraries(sm3_attack gmssl -lomp)
