cmake_minimum_required(VERSION 3.10)
project(libsafe C)

set(CMAKE_C_STANDARD 90)

add_compile_options(-Wno-format-truncation)

add_library(purec-static STATIC
#        common.h
)
set_target_properties(purec-static PROPERTIES OUTPUT_NAME "purec")

add_library(purec-shared SHARED
#        common.h
)
set_target_properties(purec-shared PROPERTIES OUTPUT_NAME "purec")

#add_subdirectory(examples)

