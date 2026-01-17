# crypto

Cryptography and related functions library written for recreation purpose.

## Building

Clone the repository and launch the script `build.sh`, go in the build directory and execute `make`. The default building type is defined in the script and it is ***Release***.

## Usage

Usage is really simple just include the files that you need or direcly `<crypto/crypto.hpp>` to include them all. The API are straightforward.

### Example

```cpp
#include <iostream>
#include <crypto/crypto.hpp>
// or #include <crypto/hash.hpp>

int main()
{
    std::cout << cypto::hash::hash_string("Hello World!", crypto::hash::algorithm::Sha256) << std::endl;
    return 0;
}
```

You can also look into the `test` directory for some examples.

## Documentation

The header files are commented with doxy documentation so they should be easy to read and understand but if you want a static documentation you can run in the root directory:

```sh
doxygen Doxyfile
```

The *html* file with the documentation will be in `docs/html/index.html`.

## Disclaimer

This library is made just for recreational purpose. If you want to use it for the same reason is okay, but do not use it in production code because it may contain bugs or implementation error.

## Dependencies

- [cmake](https://cmake.org/), build system.
- [gmp](https://gmplib.org/), for big number arithmetic.

### Optional

- [doxygen](https://www.doxygen.nl/), for building the documentation.

## Mentions

- [doxygen-awesome-css](https://github.com/jothepro/doxygen-awesome-css), for the documentation style.
