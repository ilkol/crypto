#include "crypto.h"
#include <map>
#include <algorithm>
#include <string>
#include <functional>

std::vector<QChar> Crypto::charEncodeTable = {
    {u'а'}, {u'б'}, {u'в'},
    {u'г'}, {u'д'}, {u'е'},
    {u'ё'}, {u'ж'}, {u'з'},
    {u'и'}, {u'й'}, {u'к'},
    {u'л'}, {u'м'}, {u'н'},
    {u'о'}, {u'п'}, {u'р'},
    {u'с'}, {u'т'}, {u'у'},
    {u'ф'}, {u'х'}, {u'ц'},
    {u'ч'}, {u'ш'}, {u'щ'},
    {u'ъ'}, {u'ы'}, {u'ь'},
    {u'э'}, {u'ю'}, {u'я'},

    {u'А'}, {u'Б'}, {u'В'},
    {u'Г'}, {u'Д'}, {u'Е'},
    {u'Ё'}, {u'Ж'}, {u'З'},
    {u'И'}, {u'Й'}, {u'К'},
    {u'Л'}, {u'М'}, {u'Н'},
    {u'О'}, {u'П'}, {u'Р'},
    {u'С'}, {u'Т'}, {u'У'},
    {u'Ф'}, {u'Х'}, {u'Ц'},
    {u'Ч'}, {u'Ш'}, {u'Щ'},
    {u'Ъ'}, {u'Ы'}, {u'Ь'},
    {u'Э'}, {u'Ю'}, {u'Я'},

    {u'1'}, {u'2'}, {u'3'},
    {u'4'}, {u'5'}, {u'6'},
    {u'7'}, {u'8'}, {u'9'},
    {u'0'},

    {u' '}, {u'.'}, {u','},
    {u'!'}, {u'?'}, {u'-'},
    {u':'}, {u'('}, {u')'},
};

std::optional<size_t> Crypto::getCharIndex(QChar ch) {
    auto findedChar = std::find_if(Crypto::charEncodeTable.begin(), Crypto::charEncodeTable.end(), [&ch](QChar tableChar){
        return tableChar == ch;
    });
    if(findedChar != Crypto::charEncodeTable.end()) {
        return findedChar - Crypto::charEncodeTable.begin();
    }
    return std::nullopt;
};


QString Crypto::convertCharacters(const QString& message, const QString& key, std::function<size_t(size_t, size_t)> convertor) {
    auto keyIt {key.begin()};
    QString result {""};

    for(auto ch : message) {
        std::optional<size_t> keyIndex = getCharIndex(*keyIt);
        std::optional<size_t> messageIndex = getCharIndex(ch);
        if(keyIndex && messageIndex) {
            result += charEncodeTable[convertor(keyIndex.value(), messageIndex.value())];
        } else {
            result = "Ошибка алфавита!";
            break;
        }
        if(++keyIt == key.end()) {
            keyIt = key.begin();
        }

    }

    return result;
}

QString Crypto::encrypt(const QString& message, const QString& key) {
    return convertCharacters(message, key, [](size_t keyIndex, size_t messageIndex){
        size_t encodeCharIndex = keyIndex + messageIndex;
        if(encodeCharIndex > charEncodeTable.size()) {
            encodeCharIndex -= charEncodeTable.size();
        }
        return encodeCharIndex;
    });
}

QString Crypto::decrypt(const QString& message, const QString& key) {
    return convertCharacters(message, key, [](size_t keyIndex, size_t messageIndex){
        int encodeCharIndex = messageIndex - keyIndex;
        if(encodeCharIndex < 0) {
            encodeCharIndex += charEncodeTable.size();
        }
        return static_cast<size_t>(encodeCharIndex);
    });
}
