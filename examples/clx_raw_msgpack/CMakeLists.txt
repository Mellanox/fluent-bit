set(src
  ${src}
  clx_raw_msgpack.c
  )

find_package (Threads)
add_executable(clx_raw_msgpack ${src})
target_link_libraries(clx_raw_msgpack fluent-bit-shared)
target_link_libraries(clx_raw_msgpack ${CMAKE_THREAD_LIBS_INIT})
