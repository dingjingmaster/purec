file(GLOB_RECURSE src *.h *.c)

add_library(purec-static STATIC ${src})
set_target_properties(purec-static PROPERTIES LINKER_LANGUAGE C)
set_target_properties(purec-static PROPERTIES OUTPUT_NAME "purec")

add_library(purec-shared SHARED ${src})
set_target_properties(purec-shared PROPERTIES LINKER_LANGUAGE C)
set_target_properties(purec-shared PROPERTIES OUTPUT_NAME "purec")
