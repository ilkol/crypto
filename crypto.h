#ifndef CRYPTO_H
#define CRYPTO_H

#include <QString>
#include <vector>
#include <optional>

class Crypto
{
    static std::vector<QChar> charEncodeTable;
    static std::optional<size_t> getCharIndex(QChar ch);
    static QString convertCharacters(const QString& message, const QString& key, std::function<size_t(size_t, size_t)> convertor);
public:
    Crypto() = delete;
    static QString encrypt(const QString& message);
    static QString decrypt(const QString& message);
    static QString hack(const QString& message);
};

#endif // CRYPTO_H
