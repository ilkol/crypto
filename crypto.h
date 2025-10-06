#ifndef CRYPTO_H
#define CRYPTO_H

#include <QString>
#include <unordered_map>

class Crypto
{
    static std::unordered_map<QChar, QChar> charEncodedTable;

    static std::unordered_map<QChar, QChar> charDecodeTable;

    static QChar getCharFromTable(const QChar& ch, const std::unordered_map<QChar, QChar>& map);

    static inline QChar encryptChar(const QChar& ch) {
        return getCharFromTable(ch, charEncodedTable);
    }
    static inline QChar decryptChar(const QChar& ch) {
        return getCharFromTable(ch, charDecodeTable);
    }

public:
    Crypto() = delete;

    static void Init();

    static QString encrypt(const QString& message);
    static QString decrypt(const QString& message);
    static QString hack(const QString& message);
};

#endif // CRYPTO_H
