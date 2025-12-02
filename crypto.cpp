#include "crypto.h"

#include <random>
#include <limits>

#include <boost/multiprecision/cpp_int.hpp>

using boost::multiprecision::cpp_int;

namespace {

std::mt19937_64 gen(std::random_device()());

struct KeyInfo {
    cpp_int n;
    cpp_int e;
    cpp_int d;
    cpp_int p;
    cpp_int q;
};

cpp_int generateRandomBits(uint32_t bits) {
    if(!bits) return cpp_int{0};

    cpp_int result{0};
    uint32_t chuncks = (bits + 63) / 64; // добавляем еще один чанк, чтобы в последствии гаранитровать размер числа
    for(uint32_t i{0}; i < chuncks; i++) {
        uint64_t chunk = eng();
        result |= (cpp_int(chunk) << i * 64); // заполняем число рандомными частями
    }

    uint32_t extraBits = chuncks * 64 - bits;
    if(chuncks) result &= (cpp_int(1) << bits) - 1; // зануляем лишние биты
    result |= cpp_int(1) << (bits - 1);
    result |= 1; // чтобы было простым числом, генерирую сразу нечетное
    return result;
}


cpp_int multBigIntMod(const cpp_int& base, const cpp_int& exponent, const cpp_int& mod) {
    return (a * b) % mod;
}
cpp_int powBigIntMod(const cpp_int& base, const cpp_int& exponent, const cpp_int& mod) {
    base %= mod;
    cpp_int res{1};
    while (exp > 0) {
        if ((exp & 1) != 0) {
            res = multBigIntMod(res, base, mod);
        }
        base = multBigIntMod(base, base, mod);
        exp >>= 1;
    }
    return res;
}

// расширенный алгоритм Евклида для поиска НОД и коэффициентов a*x + b*y = НОД(a,b);
cpp_int GCDExtended(const cpp_int& a, const cpp_int& b, cpp_int& x, cpp_int& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    cpp_int x1, y1;
    cpp_int g = GCDExtended(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

cpp_int inverseBigIntMod(const cpp_int& a, const cpp_int& m) {
    cpp_int x, y;
    cpp_int g = GCDExtended(a, m, x, y);
    if (g != 1) return 0;
    x %= m;
    if (x < 0) x += m;
    return x;
}

// текст простого числа Миллера-Рабина
bool isPrime(const cpp_int& number) {
    if(number < 2) return false;

    cpp_int d{n - 1};
    uint32_t s{0};
    for (; (d & 1) == 0; s++) {
        d >>= 1;
    }

    std::uniform_int_distribution<uint64_t> dist64(2, std::numeric_limits<uint53_t>.max() - 1);
    for (size_t i {0}; i < 8; i++) {
        cpp_int a {dist64(rng_engine)};
        a %= number - 4;
        a += 2;
        cpp_int x = powBigIntMod(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool composite{true};
        for (unsigned r = 1; r < s; ++r) {
            x = multBigIntMod(x, x, n);
            if (x == n-1) {
                composite = false;
                break;
            }
        }
        if (composite)
            return false;
    }
    return true;
}

cpp_int generatePrimeNumber(uint32_t bits) {
    static auto smallPrimeNumbers = {3,5,7,11,13,17,19,23,29,31,37,41,43,47};

    while(true) {
        cpp_int number = generateRandomBits(bits);
        for(auto p : smallPrimeNumbers) { // проверка, что не делится на маленькие простые
            if(number % p) {
                number += 2; // если делиться, то проверим следующее нечетное
            }
        }

        if(isPrime(number)) {
            return number;
        }
    }
}

void generateKey(const cpp_int& e, const cpp_int& n, const cpp_int d) {
    p = generatePrimeNumber(512);
    do {
        q = generatePrimeNumber(512);
    } while(q == p);
    n = p * q;
    cpp_int phi{(p - 1) * (q - 1)};

    e = 65537;
    if(boost::multiprecision::gcd(e, phi) != 1) {
        e = 3;
        while(boost::multiprecision::gcd(e, phi) != 1) {
            e += 2;
        }
    }
    d = inverseBigIntMod(e, phi);
    if(d == 0) {
        throw std::exception("Failed to generate key");
    }
}

cpp_int bytesToInt(const std::vector<uint8_t>& in) {
    cpp_int x = 0;
    for (uint8_t b : in) {
        x <<= 8;
        x += b;
    }
    return x;
}

}



QString Crypto::encrypt(const QString& message, const QString& key) {
    QByteArray utf8Message = message.toUtf8();
    std::vector<uint8_t> bytes(utf8Message.begin(), utf8Message.end());

    cpp_int m = bytesToInt(bytes);

    return "Зашифровал";
}

QString Crypto::decrypt(const QString& message, const QString& key) {
    return "Расшифровал";
}
