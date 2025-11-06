#ifndef CRYPTO_H
#define CRYPTO_H

#include <QString>

class Crypto
{
public:
    Crypto() = delete;
    static QString encrypt(const QString& message, const QString& key);
    static QString decrypt(const QString& message, const QString& key);
};

#endif // CRYPTO_H
