# crypto

Cryptography library written for recreation purpose. For now it includes base64 encoding functions and secure hash familty functions.

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
    std::cout << cypto::sha::HashString("Hello World!", crypto::sha::Algorithm::Sha256) << std::endl;
    return 0;
}
```

You can also look into the test directory for some examples.

## Dependencies

- [cmake](https://cmake.org/), build system.
