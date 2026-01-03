cmake_minimum_required(VERSION 3.15...4.1)

project(crypto VERSION 1.0 DESCRIPTION "Cryptography library written for recreation purpose " LANGUAGES CXX)
add_subdirectory(test)

add_library(
    ${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/b64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sha.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bignum.cpp
)

# GNU bignum library
find_library(GMP_LIB NAMES gmp)

if (GMP_LIB)
    target_link_libraries(${PROJECT_NAME} PUBLIC gmp)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
