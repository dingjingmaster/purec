cmake_minimum_required(VERSION 3.10)
project(purec LANGUAGES C)

set(CMAKE_C_STANDARD 90)

add_compile_options(-Wno-format-truncation)

add_subdirectory(src)
#add_subdirectory(examples)

