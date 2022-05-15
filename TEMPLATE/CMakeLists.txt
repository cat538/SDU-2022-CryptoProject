cmake_minimum_required (VERSION 3.8)

project ("project-cpp")
set(CMAKE_CXX_STANDARD 17)

message("CMAKE_PROJECT_NAME: ${CMAKE_PROJECT_NAME}")
message("CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message("PLATFORM: ${CMAKE_SYSTEM_NAME}")
message("CMAKE_CXX_COMPILER_ID: ${CMAKE_CXX_COMPILER_ID}")
message("PROJECT_SOURCE_DIR: ${PROJECT_SOURCE_DIR}")
message("default flag: ${CMAKE_CXX_FLAGS}")
message("debug flag: ${CMAKE_CXX_FLAGS_DEBUG}")
message("release flag: ${CMAKE_CXX_FLAGS_RELEASE}")
# -march = native 自检测cpu对程序优化
# -Wl 将后面的参数传给linker --no-as-needed 不忽略链接时没有用到的动态库
if(${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        # set(CMAKE_CXX_FLAGS_DEBUG "-g -Wall -Wunused-function -pthread -maes -Wl,--no-as-needed -ldl")
        # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -g -pthread -maes")
        message("gcc - Debug mode")
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" ) 
        # set(CMAKE_CXX_FLAGS_RELEASE "-Ofast -DNDEBUG -pthread -march=native -pipe -Wl,--no-as-needed -ldl")
        # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Ofast -pthread -maes")
        message("gcc - Release mode")
    endif()
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL "MSVC")
    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        message("MSVC - Debug mode")
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" ) 
        message("MSVC - Release mode")
    endif()
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        message("MSVC - Debug mode")
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" ) 
        message("MSVC - Release mode")
    endif()
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL "AppleClang")
    if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
        message("MSVC - Debug mode")
    elseif( CMAKE_BUILD_TYPE STREQUAL "Release" ) 
        message("MSVC - Release mode")
    endif()
endif()

message("release flag: ${CMAKE_CXX_FLAGS_RELEASE}")


# 头文件目录
include_directories("${PROJECT_SOURCE_DIR}/include")

# 链接库目录
if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    link_directories(${PROJECT_SOURCE_DIR}/lib/linux)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    link_directories(${PROJECT_SOURCE_DIR}/lib/win)
else(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    link_directories(${PROJECT_SOURCE_DIR}/lib/mac)
endif()

# 指定生成二进制文件目录
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/out)

# 查找当前目录下的所有源文件, 保存到 DIR_SRCS
aux_source_directory(./src DIR_SRCS)

# 将源代码添加到此项目的可执行文件。
add_executable (${CMAKE_PROJECT_NAME} ${DIR_SRCS})

# # 链接库
# if(${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
#     target_link_libraries(DiscreteLog crypto)
# else()
#     target_link_libraries(DiscreteLog libcrypto)
# endif()

# # 包含子项目
# add_subdirectory ("subproject")