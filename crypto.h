#ifndef CRYPTO_H
#define CRYPTO_H

#include <QString>
#include <unordered_map>

class Crypto
{
    static std::unordered_map<QChar, QChar> charEncodedTable;

    static std::unordered_map<QChar, QChar> charDecodeTable;

public:
    Crypto() = delete;

    static void Init();

    static QString encrypt(const QString& message);
    static QString decrypt(const QString& message);
    static QString hack(const QString& message);
};

#endif // CRYPTO_H
