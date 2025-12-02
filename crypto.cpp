#include "crypto.h"

#include <functional>
#include <vector>
#include <bit>
#include <random>
#include <QByteArray>
#include <QtEndian>

namespace {
struct CryptoOperation {
    std::function<void(QByteArray&)> encrypt;
    std::function<void(QByteArray&)> decrypt;
};
using CryptoOperationsVector = std::vector<CryptoOperation>;

struct EncryptSettings {
    uint8_t blockSize;
    uint8_t operationsCount;
    uint8_t bytShiftStep;
};

uint64_t readBlock(const QByteArray &source, size_t offset, size_t blockSize)
{
    uint64_t v = 0;
    if (offset + blockSize > source.size()) {
        throw std::out_of_range("readBlock out of range");
    }
    for (size_t i = 0; i < blockSize; ++i) {
        v = (v << 8) | static_cast<uint8_t>(source[offset + i]);
    }
    return v;
}

void writeBlock(QByteArray &destination, qsizetype offset, uint64_t value, size_t blockSize)
{
    if (offset + static_cast<qsizetype>(blockSize) > destination.size()) {
        throw std::out_of_range("writeBlock out of range");
    }
    for (size_t i = 0; i < blockSize; ++i) {
        size_t shift = 8 * (blockSize - 1 - i);
        destination[offset + static_cast<qsizetype>(i)] = static_cast<char>((value >> shift) & 0xFF);
    }
}


auto generateTable(uint64_t key, uint16_t tableSize) {
    std::vector<uint8_t> result;
    result.reserve(tableSize);
    for(uint16_t i{0}; i < tableSize; i++) {
        result.push_back(i);
    }

    std::mt19937 gen(key);
    std::shuffle(result.begin(), result.end(), gen);

    return result;
}
auto inverTable(std::vector<uint8_t> table) {
    std::vector<uint8_t> result{};
    result.reserve(table.size());
    for(uint16_t i{0}; i < table.size(); i++) {
        result.push_back(i);
    }

    for (uint16_t i = 0; i < table.size(); ++i) {
        result[table[i]] = i;
    }

    return result;
}


CryptoOperationsVector generateOperations(uint64_t key, EncryptSettings settings) {
    CryptoOperationsVector result;

    std::mt19937_64 gen(key);
    std::uniform_int_distribution<uint8_t>
        operatioTypeDist(0, 4),
        boolDist(0, 1),
        modAddDist(8, 63)
    ;

    for(size_t i{0}; i < settings.operationsCount; i++) {
        uint8_t operationType{operatioTypeDist(gen)};
        CryptoOperation op;

        switch(operationType) {
        case 0: // замена
        {
            auto table {generateTable(key + i, 256)}; // чтобы для каждой новой операции была уникальная таблица
            auto invTable {inverTable(table)};

            op.encrypt = [table](QByteArray& message) {
                QByteArray out(message.size(), 0);
                for(size_t i{0}; i < message.size(); i ++) {
                    uint8_t val = static_cast<uint8_t>(message[i]);
                    out[i] = static_cast<uchar>((val < 256) ? table[val] : val);
                }
                message = out;
            };
            op.decrypt = [invTable](QByteArray& message) {
                QByteArray out(message.size(), 0);
                for(size_t i{0}; i < message.size(); i ++) {
                    uint8_t val = static_cast<uint8_t>(message[i]);
                    out[i] = static_cast<char>(invTable[val]);
                }
                message = out;
            };

        }
            break;
        case 1: // перестановка
        {
            auto table {generateTable(key + 1, settings.blockSize)};
            auto invTable {inverTable(table)};

            op.encrypt = [settings, table](QByteArray& message) {
                QByteArray out(message.size(), 0);
                for(size_t i{0}; i < message.size(); i ++) {
                    uint8_t index = i % settings.blockSize;
                    writeBlock(out, i, message[i - index + table[index]], 1);
                }
                message = out;
            };
            op.decrypt = [settings, invTable](QByteArray& message) {
                QByteArray out(message.size(), 0);
                for(size_t i{0}; i < message.size(); i ++) {
                    uint8_t index = i % settings.blockSize;
                    writeBlock(out, i, message[i - index + invTable[index]], 1);
                }
                message = out;
            };

        }
            break;
        case 2: // сдвиг
        {
            bool type {boolDist(gen)};
            op.encrypt = [settings, type](QByteArray& message) {
                size_t bits = settings.blockSize * 8; // количество бит в блоке
                uint64_t mask = (settings.blockSize == 8) ? ~0ULL : ((1ULL << bits) - 1);

                for(size_t i = 0; i < message.size(); i += settings.blockSize) {
                    uint64_t block = readBlock(message, i, settings.blockSize);

                    if(type) {
                        block = ((block << settings.bytShiftStep) | (block >> (bits - settings.bytShiftStep))) & mask;
                    } else {
                        block = ((block >> settings.bytShiftStep) | (block << (bits - settings.bytShiftStep))) & mask;
                    }

                    writeBlock(message, i, block, settings.blockSize);
                }
            };
            op.decrypt = [settings, type](QByteArray& message) {
                size_t bits = settings.blockSize * 8;
                uint64_t mask = (settings.blockSize == 8) ? ~0ULL : ((1ULL << bits) - 1);

                for(size_t i = 0; i < message.size(); i += settings.blockSize) {
                    uint64_t block = readBlock(message, i, settings.blockSize);

                    if(type) {
                        // направление сдвига противоположное шифрованию
                        block = ((block >> settings.bytShiftStep) | (block << (bits - settings.bytShiftStep))) & mask;
                    } else {
                        block = ((block << settings.bytShiftStep) | (block >> (bits - settings.bytShiftStep))) & mask;
                    }

                    writeBlock(message, i, block, settings.blockSize);
                }
            };
        }

            break;
        case 3: // mod 2^n
        {
            bool type {boolDist(gen) > 0};
            size_t mid = settings.blockSize / 2;
            uint8_t maxBits = static_cast<uint8_t>(mid * 8);
            uint8_t n {modAddDist(gen)};
            uint64_t mask = ((1ULL << n) - 1);

            auto add = [mask](uint64_t a, uint64_t b) { return (a + b) & mask; };
            auto sub = [mask](uint64_t a, uint64_t b) { return (a - b) & mask; };

            op.encrypt = [settings, type, add, mid](QByteArray& message) {

                for(size_t i{0}; i < message.size(); i += 2 * mid) {
                    uint64_t
                        L { readBlock(message, i, mid) },
                        R { readBlock(message, i + mid, mid) }
                    ;
                    if(type) {
                        L = add(L, R);
                    } else {
                        R = add(R, L);
                    }

                    writeBlock(message, i, L, mid);
                    writeBlock(message, i + mid, R, mid);
                }
            };
            op.decrypt = [settings, type, sub, mid](QByteArray& message) {
                for(size_t i{0}; i < message.size(); i += 2 * mid) {
                    uint64_t
                        L { readBlock(message, i, mid) },
                        R { readBlock(message, i + mid, mid) }
                    ;
                    if(type) {
                        L = sub(L, R);
                    } else {
                        R = sub(R, L);
                    }

                    writeBlock(message, i, L, mid);
                    writeBlock(message, i + mid, R, mid);
                }
            };

        }
        break;
        case 4: // + mod 2
        {
            auto opFunc = gen() % 2
                              ? [](uint64_t& L, uint64_t& R) { L ^= R; }
                              : [](uint64_t& L, uint64_t& R) { R ^= L; }
            ;
            size_t mid{ settings.blockSize / 2};

            op.decrypt = op.encrypt = [settings, opFunc, mid](QByteArray& message) {
                for(size_t i{0}; i < message.size(); i += settings.blockSize) {
                    uint64_t
                        L { readBlock(message, i, mid) },
                        R { readBlock(message, i + mid, mid) }
                    ;

                    opFunc(L, R);

                    writeBlock(message, i, L, mid);
                    writeBlock(message, i + mid, R, mid);
                }
            };

        }
            break;
        }

        result.push_back(op);

    }


    return result;
}

}
QByteArray addPadding(const QByteArray& data, uint8_t blockSize){
    uint8_t paddingLength = blockSize - (data.size() % blockSize);
    QByteArray res = data;
    res.append(paddingLength, static_cast<uchar>(paddingLength));
    return res;
}

QByteArray deletePadding(const QByteArray& data, uint8_t blockSize){
    if(data.isEmpty()) return data;
    uint8_t paddingLength{static_cast<uchar>(data.back())};
    return (paddingLength > blockSize)
       ? data
       : data.left(data.size() - paddingLength)
    ;
}

QString Crypto::encrypt(const QString& message, const QString& key) {
    QByteArray utf8Key = key.toUtf8();
    if(utf8Key.size() < 8) {
        return "Неверный ключ";
    }

    uint64_t secretKey {qFromBigEndian<uint64_t>(reinterpret_cast<const uchar*>(utf8Key.mid(0, 8).data()))};

    std::mt19937_64 gen(secretKey);
    std::uniform_int_distribution<uint8_t>
        blockSizeDist(1, 4),
        operatorsCountDist(1, 10),
        bytShiftStepDist(1, 15)
    ;

    uint8_t
        blockSize{ blockSizeDist(gen) * 2 }, // гарантированно кратно двум, чтобы потом можжно было бы делить на два блока
        operatorsCount{operatorsCountDist(gen)},
        bytShiftStep{bytShiftStepDist(gen)}
    ;

    QByteArray utf8Messag = addPadding(message.toUtf8(), blockSize);

    CryptoOperationsVector operations = generateOperations(secretKey, {
        blockSize,
        operatorsCount,
        bytShiftStep
    });

    try {
        for(auto op : operations) {
            op.encrypt(utf8Messag);
        }
    } catch(...) {
        return "Программа завершилась с ошибкой.";
    }

    return utf8Messag.toHex();
}

QString Crypto::decrypt(const QString& message, const QString& key) {
    QByteArray utf8Key = key.toUtf8();
    if(utf8Key.size() < 8) {
        return "Неверный ключ";
    }

    uint64_t secretKey {qFromBigEndian<uint64_t>(reinterpret_cast<const uchar*>(utf8Key.mid(0, 8).data()))};

    std::mt19937_64 gen(secretKey);
    std::uniform_int_distribution<uint8_t>
        blockSizeDist(1, 4),
        operatorsCountDist(1, 10),
        bytShiftStepDist(1, 15)
        ;

    uint8_t
        blockSize{ blockSizeDist(gen) * 2 }, // гарантированно кратно двум, чтобы потом можжно было бы делить на два блока
        operatorsCount{operatorsCountDist(gen)},
        bytShiftStep{bytShiftStepDist(gen)}
    ;
    QByteArray utf8Messag = QByteArray::fromHex(message.toUtf8());

    CryptoOperationsVector operations = generateOperations(secretKey, {
        blockSize,
        operatorsCount,
        bytShiftStep
    });

    try {
        for(auto op = operations.end() - 1; op != operations.begin(); op--) {
            (*op).decrypt(utf8Messag);
        }
        auto op = *operations.begin();
        op.decrypt(utf8Messag);
    } catch(...) {
        return "Программа завершилась с ошибкой.";
    }


    return QString::fromUtf8(deletePadding(utf8Messag, blockSize));
}
