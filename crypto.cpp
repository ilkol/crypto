#include "crypto.h"

#include <array>
#include <QByteArray>
#include <QtEndian>
#include <stdexcept>
#include <functional>
#include <bit>

namespace {
constexpr uint8_t table[8][16] = {
    {12, 7, 15, 5, 0, 14, 2, 4, 10, 13, 9, 3, 8, 1, 6, 11},
    {0, 14, 4, 9, 8, 2, 12, 15, 6, 1, 7, 11, 10, 13, 5, 3},
    {3, 15, 11, 0, 9, 7, 1, 2, 5, 13, 4, 12, 14, 10, 6, 8},
    {0, 10, 8, 3, 15, 12, 14, 4, 11, 9, 6, 2, 7, 13, 1, 5},
    {11, 8, 5, 10, 0, 2, 9, 12, 3, 7, 14, 13, 6, 1, 4, 15},
    {6, 4, 11, 9, 12, 3, 10, 15, 8, 7, 5, 14, 2, 1, 0, 13},
    {13, 9, 3, 14, 7, 5, 11, 10, 8, 1, 0, 15, 6, 4, 2, 12},
    {13, 2, 0, 9, 4, 1, 12, 15, 8, 11, 10, 3, 14, 6, 5, 7}
};

inline std::array<uint32_t, 8> splitKeys(const QString& key) {
    QByteArray keysArray = key.toUtf8();
    if(keysArray.size() < 32) {
        throw std::invalid_argument("Неверный секретный ключ");
    }

    std::array<uint32_t, 8> secretKeys{0};
    for(size_t i{0}, shift{0}; i < 8; i++, shift += 4){
        secretKeys[i] =
            (static_cast<uint32_t>(static_cast<unsigned char>(keysArray[shift + 0])) << 24) |
            (static_cast<uint32_t>(static_cast<unsigned char>(keysArray[shift + 1])) << 16) |
            (static_cast<uint32_t>(static_cast<unsigned char>(keysArray[shift + 2])) << 8) |
            (static_cast<uint32_t>(static_cast<unsigned char>(keysArray[shift + 3])));
    }
    return secretKeys;
}

uint32_t F(uint32_t x){
    uint32_t result = 0;
    for(size_t i{0}, shift{0}; i < 8; i++, shift += 4){
        uint8_t block = (x >> shift) & 0b1111;
        result |= table[i][block] << shift;
    }
    return result;
}

QByteArray modifyMessage(const QByteArray& message, std::function<void (size_t i, uint32_t& L, uint32_t& R)> modifire) {
    if(message.size() != 8){
        throw std::invalid_argument("Блок должен быть 8 байт");
    }

    uint32_t
        L {qFromBigEndian<uint32_t>(reinterpret_cast<const uchar*>(message.data()))},
        R {qFromBigEndian<uint32_t>(reinterpret_cast<const uchar*>(message.data()+4))}
    ;

    for(size_t i{1}; i <= 32; i++){
        modifire(i, L, R);
    }

    QByteArray out(8, 0);
    qToBigEndian(L, reinterpret_cast<uchar*>(out.data()));
    qToBigEndian(R, reinterpret_cast<uchar*>(out.data() + 4));
    return out;
}

inline void messageModificationIteration(const std::array<uint32_t,8>& keys, uint32_t& L, uint32_t& R, size_t j) {
    uint32_t V = R;
    /*
     * R = (R + Q(j)) mod 2^32
     * R = F(R)
     * R = R <<< 11
     * R = (L + R) mod 8
     */
    R = L ^ std::rotl(F(R + keys[j]), 11);
    L = V;
}

inline size_t keyIndexCalculator(size_t i, size_t maxIndex) {
    return (i < maxIndex) ? ((i - 1) % 8) : ((32 - i) % 8);
}

QByteArray encryptMessage(const QByteArray& message, const std::array<uint32_t,8>& keys){
    return modifyMessage(message, [&keys](size_t i, uint32_t& L, uint32_t& R) {
        messageModificationIteration(keys, L, R, keyIndexCalculator(i, 25));
    });
}

QByteArray decryptMessage(const QByteArray& message, const std::array<uint32_t,8>& keys){
    return modifyMessage(message, [&keys](size_t i, uint32_t& L, uint32_t& R) {
        messageModificationIteration(keys, R, L, keyIndexCalculator(i, 9));
    });
}

QByteArray addPadding(const QByteArray& data){
    uint8_t paddingLength = 8 - (data.size() % 8);
    QByteArray res = data;
    res.append(paddingLength, static_cast<uchar>(paddingLength));
    return res;
}

QByteArray deletePadding(const QByteArray& data){
    if(data.isEmpty()) return data;
    uint8_t paddingLength{static_cast<uchar>(data.back())};
    return (paddingLength <= 0 || paddingLength > 8)
        ? data
        : data.left(data.size() - paddingLength)
    ;
}

// E_(H_(i-1) ) (M_i )
QByteArray functionE(const QByteArray& msgBytes, const QString& key) {
    std::array<uint32_t, 8> keys = splitKeys(key);
    return encryptMessage(msgBytes, keys);
}

QByteArray operator^(const QByteArray& left, const QByteArray& right) {
    qsizetype size = std::min(left.size(), right.size());
    QByteArray result(size, 0);

    for (qsizetype i{0}; i < size; i++) {
        result[i] = left[i] ^ right[i];
    }
    return result;
}

// H_i=E_(H_(i-1) ) (M_i )  ⨁M_i  ⨁H_(i-1)
QString hash(const QByteArray& message, const QString& h) {
    if (message.size() != 8) {
        throw std::invalid_argument("Сообщение должно быть ровно 8 байт");
    }

    QByteArray result = functionE(message, h);
    QByteArray hBytes = h.toUtf8();

    result = result ^ message ^ hBytes;

    return result.toHex();
}


}

QString Crypto::encrypt(const QString& message, const QString& key){
    try {
        QByteArray msgBytes = addPadding(message.toUtf8());

        QString h = key;
        QString result = "";
        for(size_t i{0}; i < msgBytes.size(); i += 8) {
            QByteArray chunk = msgBytes.mid(i, 8);
            result += h = hash(chunk, h);
        }

        return result;

    } catch(std::invalid_argument& e) {
        return e.what();
    }
    return "Программа завершилась с ошибкой";
}

QString Crypto::decrypt(const QString& message, const QString& key){
    std::array<uint32_t, 8> keys;
    try {
        keys = splitKeys(key);
        QByteArray msgBytes = QByteArray::fromHex(message.toUtf8());
        QByteArray out;
        for(size_t i{0}; i < msgBytes.size(); i += 8){
            out += decryptMessage(msgBytes.mid(i, 8), keys);
        }
        return QString::fromUtf8(deletePadding(out));
    } catch(std::invalid_argument& e) {
        return e.what();
    }
    return "Программа завершилась с ошибкой";

}
