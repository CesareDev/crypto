# crypto

Cryptography and related functions library written for recreation purpose.

## Building

Clone the repository and launch the script `build.sh`, go in the build directory and execute `make`. The building type is defined in the script as ***Release***.

## Usage

Usage is really simple just include the files that you need or direcly `<crypto/crypto.hpp>` to include them all. The API are straightforward.

### Example

```cpp
#include <iostream>
#include <crypto/crypto.hpp>
// or #include <crypto/sha.hpp>

int main()
{
    std::cout << cypto::sha::hash_string("Hello World!", crypto::sha::algorithm::Sha256) << std::endl;
    return 0;
}
```

You can also look into the `test` directory for some examples.

## Disclaimer

This library is made just for recreational purpose. If you want to use it for the same reason is okay, but do not use it in production code because it may contain bugs or implementation error.

## Dependencies

- [cmake](https://cmake.org/), build system.
- [gmp](https://gmplib.org/) for big number arithmetic.
