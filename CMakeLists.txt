cmake_minimum_required(VERSION 3.15...4.1)

project(crypto VERSION 1.0 DESCRIPTION "Cryptography library written for recreation purpose " LANGUAGES CXX)
add_subdirectory(test)

add_library(
    ${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/b64.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sha.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
