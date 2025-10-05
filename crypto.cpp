#include "crypto.h"

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

QString Crypto::encrypt(const QString& message) {

    QString result{};
    result.reserve(charDecodeTable.size());

    return result;
}

QString Crypto::decrypt(const QString& message) {
    QString result{};
    result.reserve(charDecodeTable.size());

    return "Расшифровал";
}

QString Crypto::hack(const QString& message) {
    QString result{};
    result.reserve(charDecodeTable.size());

    return "Взломал";
}
