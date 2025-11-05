#include "crypto.h"

#include <map>

std::unordered_map<double, QChar> Crypto::lettersFrequency = {
    {0.10983, u'о'}, {0.08483 , u'е'}, {0.07998, u'а'},
    {0.07367, u'и'}, {0.067 , u'н'}, {0.06318, u'т'},
    {0.05473, u'с'}, {0.04746 , u'р'}, {0.04533, u'в'},
    {0.04343, u'л'}, {0.03486 , u'к'}, {0.03203, u'м'},
    {0.02977, u'д'}, {0.02804 , u'п'}, {0.02615 , u'у'},
    {0.02001, u'я'}, {0.01898 , u'ы'}, {0.01735 , u'ь'},
    {0.01687, u'г'}, {0.01641 , u'з'}, {0.01592 , u'б'},
    {0.0145, u'ч'}, {0.01208 , u'й'}, {0.00966 , u'х'},
    {0.0094, u'ж'}, {0.00718 , u'ш'}, {0.00639 , u'ю'},
    {0.00486, u'ц'}, {0.00361 , u'щ'}, {0.00331 , u'э'},
    {0.00267, u'ф'}, {0.00037 , u'ъ'}, {0.00013 , u'ё'},
};

std::unordered_map<QChar, QChar> Crypto::charEncodedTable = {
    {u'а', u'='}, {u'б', u'ю'}, {u'в', u'у'},
    {u'г', u'9'}, {u'д', u'!'}, {u'е', u'Э'},
    {u'ё', u'1'}, {u'ж', u'л'}, {u'з', u'Ш'},
    {u'и', u','}, {u'й', u'в'}, {u'к', u'п'},
    {u'л', u'?'}, {u'м', u'Ю'}, {u'н', u'ш'},
    {u'о', u'и'}, {u'п', u' '}, {u'р', u'П'},
    {u'с', u'б'}, {u'т', u'М'}, {u'у', u'Х'},
    {u'ф', u'7'}, {u'х', u'А'}, {u'ц', u'Ч'},
    {u'ч', u'Г'}, {u'ш', u'с'}, {u'щ', u'О'},
    {u'ъ', u')'}, {u'ы', u'к'}, {u'ь', u'Л'},
    {u'э', u'Ы'}, {u'ю', u'И'}, {u'я', u'Р'},

    {u'А', u'Ф'}, {u'Б', u'.'}, {u'В', u'м'},
    {u'Г', u'Й'}, {u'Д', u'Т'}, {u'Е', u'н'},
    {u'Ё', u'Е'}, {u'Ж', u'ё'}, {u'З', u'г'},
    {u'И', u'З'}, {u'Й', u'8'}, {u'К', u'ъ'},
    {u'Л', u'х'}, {u'М', u'е'}, {u'Н', u'К'},
    {u'О', u'Ъ'}, {u'П', u'д'}, {u'Р', u'-'},
    {u'С', u'Б'}, {u'Т', u'я'}, {u'У', u':'},
    {u'Ф', u'0'}, {u'Х', u'ь'}, {u'Ц', u'т'},
    {u'Ч', u'Ц'}, {u'Ш', u'У'}, {u'Щ', u'Щ'},
    {u'Ъ', u'Я'}, {u'Ы', u'Д'}, {u'Ь', u'ы'},
    {u'Э', u'Н'}, {u'Ю', u'ж'}, {u'Я', u'В'},

    {u'1', u'С'}, {u'2', u'й'}, {u'3', u'2'},
    {u'4', u'р'}, {u'5', u'5'}, {u'6', u'а'},
    {u'7', u'Ь'}, {u'8', u'ф'}, {u'9', u'3'},
    {u'0', u'ч'},

    {u' ', u'о'}, {u'.', u'з'}, {u',', u'Ё'},
    {u'!', u'щ'}, {u'?', u'ц'}, {u'-', u'э'},
    {u':', u'4'}, {u'(', u'Ж'}, {u')', u'6'},
};

std::unordered_map<QChar, QChar> Crypto::charDecodeTable{};

void Crypto::Init() {
    charDecodeTable.reserve(charEncodedTable.size());
    for(const auto& pair : charEncodedTable) {
        charDecodeTable[pair.second] = pair.first;
    }
}

QChar Crypto::getCharFromTable(const QChar& ch, const std::unordered_map<QChar, QChar>& map) {
    auto it = map.find(ch);
    if(it == map.end()) {
        return ch;
    }
    return it->second;
}

QString Crypto::translateMessageByTable(const QString& message, const std::unordered_map<QChar, QChar>& map) {
    QString result{};
    result.reserve(message.size());

    for(const auto& ch : message) {
        result += getCharFromTable(ch, map);
    }

    return result;
}

inline bool isEqueal(double a, double b, double epsilon) {
    return std::abs(a - b) < epsilon;
}

std::unordered_map<QChar, QChar> Crypto::hackTableByFrequency(std::map<QChar, double> frequency) {
    std::unordered_map<QChar, QChar> result{};

    for(const auto& frequencyPair : frequency) {
        const auto& pair = std::find_if(lettersFrequency.begin(), lettersFrequency.end(), [frequencyPair](const auto& element) {
            return isEqueal(element.first, frequencyPair.second, 0.001);
        });
        if(pair != lettersFrequency.end()) {
            result[frequencyPair.first] = pair->second;
        }
    }
    return result;
}

QString Crypto::hack(const QString& message) {

    std::map<QChar, double> frequencyTable{};

    // собираем количество вхождений символов
    for(const QChar& ch : message) {
        auto it = frequencyTable.find(ch);
        if(it == frequencyTable.end()) {
            frequencyTable[ch] = 1.0;
            continue;
        }
        it->second++;
    }

    qsizetype size = message.length();


    QString result{};
    result.reserve(charDecodeTable.size());

    // считаем частоту вхождений каждого символа
    for(auto& pair : frequencyTable) {
        pair.second /= size;
    }

    const auto table = hackTableByFrequency(frequencyTable);

    result = translateMessageByTable(message, table);

    for(auto& pair : table) {
        result += pair.first;
        result += " - ";
        result += pair.second;
        result += '\n';
    }
    for(auto& pair : frequencyTable) {
        result += pair.first;
        result += " - ";
        result += std::to_string(pair.second);
        result += '\n';
    }


    return result;
}
