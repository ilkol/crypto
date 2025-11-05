#ifndef CRYPTO_H
#define CRYPTO_H

#include <QString>
#include <unordered_map>
#include <map>

class Crypto
{

    static std::unordered_map<double, QChar> lettersFrequency;

    static std::unordered_map<QChar, QChar> charEncodedTable;

    static std::unordered_map<QChar, QChar> charDecodeTable;

    static QChar getCharFromTable(const QChar& ch, const std::unordered_map<QChar, QChar>& map);

    static QString translateMessageByTable(const QString& message, const std::unordered_map<QChar, QChar>& map);

    static std::unordered_map<QChar, QChar> hackTableByFrequency(std::map<QChar, double> frequency);

public:
    Crypto() = delete;

    static void Init();

    static inline QString encrypt(const QString& message) {
        return translateMessageByTable(message, charEncodedTable);
    }
    static inline QString decrypt(const QString& message) {
        return translateMessageByTable(message, charDecodeTable);
    }
    static QString hack(const QString& message);
};

#endif // CRYPTO_H
