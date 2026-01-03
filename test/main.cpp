#include <crypto/crypto.hpp>

#include <iostream>

int main()
{
    std::string s { "Hello World!" };

    std::cout << "Hashing function on the string: " << s << std::endl;
    std::cout << "Sha1:   " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha1) << std::endl;
    std::cout << "Sha224: " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha224) << std::endl;
    std::cout << "Sha256: " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha256) << std::endl;
    std::cout << "Sha384: " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha384) << std::endl;
    std::cout << "Sha512: " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha512) << std::endl;

    std::cout << std::endl;

    std::cout << "Encoding of: " << s << std::endl;
    std::cout << "Base64: " << crypto::b64::EncodeString("Hello World!") << std::endl;

    std::cout << std::endl;

    crypto::bn::bignum a("123456789123456789123456789123456789123456789", 10);
    crypto::bn::bignum b("123456789123456789123456789123456789123456789", 10);
    std::cout << "Big num a: " << a << std::endl;
    std::cout << "Big num b: " << a << std::endl;
    std::cout << "Big num a * b: " << a * b << std::endl;

    return 0;
}
