cmake_minimum_required(VERSION 3.10)
project(MiniIDS)

set(CMAKE_CXX_STANDARD 17)

find_library(PCAP_LIBRARY pcap)

add_executable(mini_ids src/main.cpp)
target_link_libraries(mini_ids ${PCAP_LIBRARY})
