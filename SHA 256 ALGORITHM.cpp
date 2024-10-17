#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>

// Defining a Message type for easier handling
using Message = std::vector<uint8_t>;

// Constants as per the pseudocode
const std::array<uint32_t, 8> INITIAL_HASH = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

const std::array<uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Helper functions
uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// Pre-processing (Padding)
Message preprocess(const std::string& input) {
    Message message(input.begin(), input.end());
    uint64_t original_bit_length = message.size() * 8;

    message.push_back(0x80);
    while ((message.size() * 8 + 64) % 512 != 0) {
        message.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        message.push_back((original_bit_length >> (i * 8)) & 0xFF);
    }

    return message;
}

// Process the message in successive 512-bit chunks
std::array<uint32_t, 8> process_chunks(const Message& message) {
    std::array<uint32_t, 8> hash = INITIAL_HASH;

    for (size_t chunk = 0; chunk < message.size(); chunk += 64) {
        std::array<uint32_t, 64> w;

        // Create message schedule
        for (int i = 0; i < 16; ++i) {
            w[i] = (message[chunk + 4 * i] << 24) | (message[chunk + 4 * i + 1] << 16) |
                (message[chunk + 4 * i + 2] << 8) | message[chunk + 4 * i + 3];
        }

        for (int i = 16; i < 64; ++i) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }

        // Initialize working variables
        uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3],
            e = hash[4], f = hash[5], g = hash[6], h = hash[7];

        // Compression function main loop
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Add compressed chunk to current hash value
        hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
        hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
    }

    return hash;
}

// Produce the final hash value
std::string finalize_hash(const std::array<uint32_t, 8>& hash) {
    std::stringstream ss;
    for (uint32_t h : hash) {
        ss << std::hex << std::setw(8) << std::setfill('0') << h;
    }
    return ss.str();
}

// Main SHA-256 function
std::string sha256(const std::string& input) {
    Message preprocessed = preprocess(input);
    std::array<uint32_t, 8> processed = process_chunks(preprocessed);
    return finalize_hash(processed);
}

// Function to read file content
std::string read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Unable to open file: " + filename);
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

int main() {
    try {
        std::string filename = "..\\..\\Mark textbook.txt";
        std::cout << "Reading file: " << filename << std::endl;

        std::string bookOfMark = read_file(filename);
        std::cout << "File read successfully. Size: " << bookOfMark.size() << " bytes" << std::endl;

        std::string hash = sha256(bookOfMark);
        std::cout << "SHA-256 hash code of the textbook: " << hash << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
