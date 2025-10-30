cmake_minimum_required(VERSION 3.20)
project(CryptoPP_Benchmark)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(cryptopp CONFIG REQUIRED)

add_executable(cryptopp_benchmark main.cpp)
target_link_libraries(cryptopp_benchmark PRIVATE cryptopp::cryptopp)