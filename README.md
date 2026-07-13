# c_rabbit_proj
Project based around custom Rabbit encryption algorithm implementation in C.
# NO WARANTY PROVIDED, USE AT YOUR OWN RISK

Educational project that includes 3 stages:
- Rabbit algorithm in C (32-bit and 64-bit versions)
- CLI utility that encrypts data from stdin and returns it to stdout
- ESP32 based stream cypher tool

## Building

### Lib and CLI utility
Building of project is made using root makefile.


Running `make` command will compile it with respect to OS and it's bitness.
You can also compile it with needed bitness or for all provided bitnesses (using `make rabbit32/rabbit64/all`).

PC versions run compilation with library test (using test vectors from RFC4503) and utility usage test.

You can also run profiling on 64-bit system to test 32-bit implementation against 64-bit one using `make profile`.

Use `make clean` to remove build directory and it's contents.

#### Usage
    Best way to use util from terminal is to piping or I/O redirection, since it works with stdin and stdout directly.

### ESP32 program
Project is built using IDF-ESP, root of project is in /esp/ folder.

ESP32 uses UART to recive and transmit data. Original setup for usage with Unix PC includes ESP32-WROOM32 30 pin and up to 2 USB-TTL. `make ports_setup` allows to use /dev/ttyUSB1 and /dev/ttyUSB2 to comunicate with ESP properly.

GPIO 4 used to recieve signals and GPIO 17 used to transmit signals (can be connected to one or two USB-TTL or any other UART devices). Connecting GPIO 18 and 19 will result in reset of saved key and test flag.

##### Be aware, flash encryption and custom partition table is enabled in sdkconfig.

#### Usage
If key is not found in NVS, than next recieved 16 bytes would be saved as encryption key and will not be deleted until full reset.
Key await is signaled by non-blinking blue LED.

If test flag is not found in NVS, than program will perform tests using RFC4503 testing vectors. Result of test can be seen in logs. If any test would fail than ESP would stop any data operations which is signaled by fast blue LED blinking.

If previuos steps are completed successfully than ESP would await 8 byte IV. That is signaled by slow blue LED blinking.
Next recieved 8 bytes would be saved as IV until power reset.

From this point all received data would be encrypted and outputed. If no input data present blue LED would be off, otherwise it would blink.

