#include <iostream>
#include <iomanip>

#include <crypto/crypto.hpp>

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
    std::cout << "Sha1:   " << crypto::hash::hash_string(s, crypto::hash::algorithm::SHA1).get_string(16) << std::endl;
    std::cout << "Sha224: " << crypto::hash::hash_string(s, crypto::hash::algorithm::SHA224).get_string(16) << std::endl;
    std::cout << "Sha256: " << crypto::hash::hash_string(s, crypto::hash::algorithm::SHA256).get_string(16) << std::endl;
    std::cout << "Sha384: " << crypto::hash::hash_string(s, crypto::hash::algorithm::SHA384).get_string(16) << std::endl;
    std::cout << "Sha512: " << crypto::hash::hash_string(s, crypto::hash::algorithm::SHA512).get_string(16) << std::endl;
    std::cout << "MD5:    " << crypto::hash::hash_string(s, crypto::hash::algorithm::MD5).get_string(16) << std::endl;
    std::cout << std::endl;

    std::cout << "-------- Base 64 --------" << std::endl;

    std::cout << "Encoding of: " << s << std::endl;
    std::cout << "Base64: " << crypto::b64::encode_string("Hello World!") << std::endl;
    std::cout << std::endl;

    std::cout << "-------- RSA --------" << std::endl;
    
    crypto::bn::bignum rsa_p { crypto::bn::generate_prime(1024) };
    crypto::bn::bignum rsa_q { crypto::bn::generate_prime(1024) };
    crypto::rsa::keys rsa_k { crypto::rsa::generate_keys(rsa_p, rsa_q) };
    crypto::rsa::public_key rsa_pub_k { rsa_k.pub_key };
    crypto::rsa::private_key rsa_pri_k { rsa_k.pri_key };

    std::string rsa_msg { "Hello from RSA" };
    std::cout << "Message: " << rsa_msg << std::endl;

    auto rsa_enc { crypto::rsa::encrypt_message(rsa_pub_k, rsa_msg) };
    std::cout << "Encrypt message (hex): ";
    for (uint8_t byte : rsa_enc)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
    std::cout << std::endl;

    auto rsa_dec { crypto::rsa::decrypt_message(rsa_pri_k, rsa_enc) };
    std::cout << "Decrypted message: " << rsa_dec << std::endl;
    std::cout << std::endl;

    std::cout << "-------- AES --------" << std::endl;

    std::string aes_msg { "Hello from AES" };
    std::cout << "Message: " << aes_msg << std::endl;
    crypto::aes::key aes_key { crypto::bn::generate_prime(128) };

    auto aes_enc { crypto::aes::encrypt_message(aes_key, aes_msg) };
    std::cout << "Encrypt message (hex): ";
    for (uint8_t byte : aes_enc)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
    std::cout << std::endl;

    auto aes_dec { crypto::aes::decrypt_message(aes_key, aes_enc) };
    std::cout << "Decrypted message: " << aes_dec << std::endl;
    std::cout << std::endl;
    
    std::cout << "-------- RNG --------" << std::endl;

    std::cout << std::dec << "uint64: " << crypto::rng::u64() << std::endl;
    std::cout << std::dec << "uint32: " << crypto::rng::u32() << std::endl;
    std::cout << std::dec << "uint16: " << crypto::rng::u16() << std::endl;
    std::cout << std::dec << "uint8:  " << (int)crypto::rng::u8() << std::endl;
    std::cout << std::dec << "int64:  " << crypto::rng::i64() << std::endl;
    std::cout << std::dec << "int32:  " << crypto::rng::i32() << std::endl;
    std::cout << std::dec << "int16:  " << crypto::rng::i16() << std::endl;
    std::cout << std::dec << "int8:   " << (int)crypto::rng::i8() << std::endl;
    std::cout << std::dec << "unif:   " << crypto::rng::uniform() << std::endl;

    return 0;
}
