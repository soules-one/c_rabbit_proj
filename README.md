# c_rabbit_proj
Project based around custom Rabbit encryption algorithm implementation in C.
# NO WARANTY PROVIDED, USE AT YOUR OWN RISK

Educational project that includes 3 stages:
- Rabbit algorithm in C (32-bit and 64-bit versions)
- CLI utility that encrypts data from stdin and returns it to stdout
- ESP32 based stream cypher tool (TODO)

## Building
Building of project is made using root makefile.


Running `make` command will compile it with respect to OS and it's bitness.
You can also compile it with needed bitness or for all provided bitnesses (using `make rabbit32/rabbit64/all`).

PC versions run compilation with library test (using test vectors from RFC4503) and utility usage test.

You can also run profiling on 64-bit system to test 32-bit implementation against 64-bit one using `make profile`.

Use `make clean` to remove build directory and it's contents.
