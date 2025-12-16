#ifndef CRYPTO_H
#define CRYPTO_H

#include <QString>

class Crypto
{
public:
    Crypto() = delete;
    static QString hashMessage(const QString& message, const QString& key);
};

#endif // CRYPTO_H
