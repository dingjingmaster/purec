add_executable(test-sm2 test-sm2.c)
target_link_libraries(test-sm2 PRIVATE purec-static)

add_executable(test-str test-str.c)
target_link_libraries(test-str PRIVATE purec-static)

add_test(TestSM2 test-sm2 COMMAND test-sm2)
add_test(TestStr test-str COMMAND test-str)
