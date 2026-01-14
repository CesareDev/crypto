#include <crypto/crypto.hpp>
#include <iostream>
#include <iomanip>

int main()
{
    std::cout << "-------- BIG --------" << std::endl;
    crypto::bn::bignum a { 21764937 };
    crypto::bn::bignum b("123456789123456789123456789123456789123456789", 10);
    std::cout << "Big num a: " << a << std::endl;
    std::cout << "Big num b: " << a << std::endl;
    std::cout << "Big num a * b: " << a * b << std::endl;
    std::cout << std::endl;

    std::cout << "-------- SHA --------" << std::endl;

    std::string s { "Hello World!" };
    std::cout << "Hashing function on the string: " << s << std::endl;
    std::cout << "Sha1:   " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha1).get_string(2) << std::endl;
    std::cout << "Sha224: " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha224).get_string(16) << std::endl;
    std::cout << "Sha256: " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha256).get_string(16) << std::endl;
    std::cout << "Sha384: " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha384).get_string(16) << std::endl;
    std::cout << "Sha512: " << crypto::sha::hash_string(s, crypto::sha::algorithm::Sha512).get_string(16) << std::endl;
    std::cout << std::endl;

    std::cout << "-------- B64 --------" << std::endl;
    std::cout << "Encoding of: " << s << std::endl;
    std::cout << "Base64: " << crypto::b64::encode_string("Hello World!") << std::endl;
    std::cout << std::endl;

    std::cout << "-------- RSA --------" << std::endl;
    // Number generated with https://www.numberempire.com/primenumbers.php
    crypto::bn::bignum p("179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859", 10);

    crypto::bn::bignum q("179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224138297", 10);

    std::string msg { "Hello ciao" };
    crypto::rsa::keys k = crypto::rsa::generate_keys(p, q);

    std::cout << "Message: " << msg << std::endl;
    auto enc = crypto::rsa::encrypt_message(k.pub_key, msg);
    std::cout << "Encrypt message (binary): ";
    for (uint8_t byte : enc)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)byte;
    std::cout << std::endl;
    auto dec = crypto::rsa::decrypt_message(k.pri_key, enc);
    std::cout << "Decrypted message: " << dec << std::endl;
    return 0;
}
