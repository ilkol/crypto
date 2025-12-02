#ifndef CRYPTO_H
#define CRYPTO_H

#include <QString>

#include <boost/multiprecision/cpp_int.hpp>

using boost::multiprecision::cpp_int;

class Crypto
{
public:
    Crypto() = delete;
    static QString encrypt(const QString& message);
    static QString decrypt(const QString& message);
    static QString generatePublicKey();
private:
    struct Key {
        cpp_int e;
        cpp_int n;
        cpp_int d;
    };
    static Key curentKey;
};

#endif // CRYPTO_H
