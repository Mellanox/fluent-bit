pushd /labhome/romanpr/workspace/git/fluent-bit/build/examples/clx_raw_msgpack

/usr/bin/gcc -DFLB_HAVE_ACCEPT4 -DFLB_HAVE_AWS -DFLB_HAVE_C_TLS -DFLB_HAVE_FORK -DFLB_HAVE_GMTOFF -DFLB_HAVE_INOTIFY -DFLB_HAVE_LIBBACKTRACE -DFLB_HAVE_LUAJIT -DFLB_HAVE_PARSER -DFLB_HAVE_PROXY_GO -DFLB_HAVE_RECORD_ACCESSOR -DFLB_HAVE_REGEX -DFLB_HAVE_SIGNV4 -DFLB_HAVE_SQLDB -DFLB_HAVE_STREAM_PROCESSOR -DFLB_HAVE_SYSTEMD -DFLB_HAVE_SYSTEM_STRPTIME -DFLB_HAVE_TLS -DFLB_HAVE_UNIX_SOCKET -DFLB_HAVE_UTF8_ENCODER -DFLB_HAVE_VALGRIND -DJSMN_PARENT_LINKS -DJSMN_STRICT -I/labhome/romanpr/workspace/git/fluent-bit/include -I/labhome/romanpr/workspace/git/fluent-bit/lib -I/labhome/romanpr/workspace/git/fluent-bit/lib/flb_libco -I/labhome/romanpr/workspace/git/fluent-bit/lib/rbtree -I/labhome/romanpr/workspace/git/fluent-bit/lib/msgpack-3.2.0/include -I/labhome/romanpr/workspace/git/fluent-bit/lib/chunkio/include -I/labhome/romanpr/workspace/git/fluent-bit/lib/LuaJIT-2.1.0-beta3/src -I/labhome/romanpr/workspace/git/fluent-bit/lib/monkey/include -I/labhome/romanpr/workspace/git/fluent-bit/lib/mbedtls-2.16.5/include -I/labhome/romanpr/workspace/git/fluent-bit/lib/sqlite-amalgamation-3310000 -I/labhome/romanpr/workspace/git/fluent-bit/lib/mpack-amalgamation-1.0/src -I/labhome/romanpr/workspace/git/fluent-bit/lib/miniz -I/labhome/romanpr/workspace/git/git/fluent-bit/lib/onigmo -I/labhome/romanpr/workspace/git/fluent-bit/build/include -I/labhome/romanpr/workspace/git/fluent-bit/lib/tutf8e/include -I/labhome/romanpr/workspace/git/fluent-bit/build/backtrace-prefix/include -I/labhome/romanpr/workspace/giy/fluent-bit/build/lib/msgpack-3.2.0/include  -Wall -D__FILENAME__='"/hpc/local/work/romanpr/workspace/git/fluent-bit/examples/clx_raw_msgpack/clx_raw_msgpack.c"' -g -fpic -c /labhome/romanpr/workspace/git/fluent-bit/examples/clx_raw_msgpack/clx_raw_msgpack.c 

ls -l

obj_file_2=/hpc/local/work/romanpr/workspace/git/fluent-bit/build/examples/clx_raw_msgpack/clx_raw_msgpack.o
ls -l $obj_file_2

/usr/bin/gcc -Wl,-rpath="/labhome/romanpr/workspace/git/fluent-bit/build/lib" -L/labhome/romanpr/workspace/git/fluent-bit/build/lib -lfluent-bit -shared -o librawmsgpack.so $obj_file_2 -Wl,-rpath="../../lib"
ls -l 


popd
