#include <crypto/crypto.hpp>
#include <iostream>
#include <iomanip>

int main()
{
    std::cout << "-------- Big Number --------" << std::endl;
    crypto::bn::bignum a { 21764937 };
    crypto::bn::bignum b("123456789123456789123456789123456789123456789", 10);
    std::cout << "Big num a: " << a << std::endl;
    std::cout << "Big num b: " << a << std::endl;
    std::cout << "Big num a * b: " << a * b << std::endl;
    std::cout << std::endl;

    std::cout << "-------- Hashing --------" << std::endl;

    std::string s { "Hello World!" };
    std::cout << "Hashing function on the string: " << s << std::endl;
    std::cout << "Sha1:   " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha1).get_string(16) << std::endl;
    std::cout << "Sha224: " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha224).get_string(16) << std::endl;
    std::cout << "Sha256: " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha256).get_string(16) << std::endl;
    std::cout << "Sha384: " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha384).get_string(16) << std::endl;
    std::cout << "Sha512: " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha512).get_string(16) << std::endl;
    std::cout << "MD5:    " << crypto::sha::hash_string(s, crypto::sha::algorithm::MD5).get_string(16) << std::endl;
    std::cout << std::endl;

    std::cout << "-------- Base 64 --------" << std::endl;
    std::cout << "Encoding of: " << s << std::endl;
    std::cout << "Base64: " << crypto::b64::encode_string("Hello World!") << std::endl;
    std::cout << std::endl;

    std::cout << "-------- RSA --------" << std::endl;
    
    crypto::bn::bignum p { crypto::bn::generate_prime(1024) };
    crypto::bn::bignum q { crypto::bn::generate_prime(1024) };
    crypto::rsa::keys k = crypto::rsa::generate_keys(p, q);
    crypto::rsa::public_key pub_k = { k.pub_key };
    crypto::rsa::private_key pri_k = { k.pri_key };

    std::string msg { "Hello from RSA" };
    std::cout << "Message: " << msg << std::endl;

    auto enc = crypto::rsa::encrypt_message(pub_k, msg);
    std::cout << "Encrypt message (binary): ";
    for (uint8_t byte : enc)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
    std::cout << std::endl;

    auto dec = crypto::rsa::decrypt_message(pri_k, enc);
    std::cout << "Decrypted message: " << dec << std::endl;
    return 0;
}
