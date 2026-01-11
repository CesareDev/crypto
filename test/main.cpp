#include <crypto/crypto.hpp>
#include <iostream>

#define TEST 0

int main()
{
    std::cout << "-------- SHA --------" << std::endl;

    std::string s { "Hello World!" };
    std::cout << "Hashing function on the string: " << s << std::endl;
    std::cout << "Sha1:   " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha1) << std::endl;
    std::cout << "Sha224: " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha224) << std::endl;
    std::cout << "Sha256: " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha256) << std::endl;
    std::cout << "Sha384: " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha384) << std::endl;
    std::cout << "Sha512: " << crypto::sha::HashString(s, crypto::sha::Algorithm::Sha512) << std::endl;
    std::cout << std::endl;

    std::cout << "-------- B64 --------" << std::endl;
    std::cout << "Encoding of: " << s << std::endl;
    std::cout << "Base64: " << crypto::b64::EncodeString("Hello World!") << std::endl;
    std::cout << std::endl;

    std::cout << "-------- BIG --------" << std::endl;

    crypto::bn::bignum a { 21764937 };
    crypto::bn::bignum b("123456789123456789123456789123456789123456789", 10);
    std::cout << "Big num a: " << a << std::endl;
    std::cout << "Big num b: " << a << std::endl;
    std::cout << "Big num a * b: " << a * b << std::endl;
    std::cout << std::endl;

    std::cout << "-------- RSA --------" << std::endl;
    
    auto p = 389141;
    auto q = 1581553;
    std::string msg { "Hello" };
    crypto::rsa::Keys k = crypto::rsa::GenerateKey(p, q);
    std::cout << "Message: " << msg << std::endl;
    auto enc = crypto::rsa::EncryptMessage(k.public_key, msg);
    std::cout << "Encrypted message: " << enc << std::endl;
    auto dec = crypto::rsa::DecryptMessage(k.private_key, enc);
    std::cout << "Decrypted message: " << dec << std::endl;
    return 0;
}
