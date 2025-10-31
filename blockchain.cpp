#include <iostream>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <vector>

using namespace std;

// SHA-256 implementation from scratch
class SHA256 {
private:
    uint32_t h[8];
    uint32_t k[64];
    
    uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    
    uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    uint32_t sig0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    uint32_t sig1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    uint32_t theta0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    uint32_t theta1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
    
public:
    SHA256() {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        
        uint32_t k_temp[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        
        for(int i = 0; i < 64; i++) {
            k[i] = k_temp[i];
        }
    }
    
    string hash(const string& input) {
        vector<uint8_t> padded = pad(input);
        
        for(size_t i = 0; i < padded.size(); i += 64) {
            processBlock(&padded[i]);
        }
        
        stringstream ss;
        for(int i = 0; i < 8; i++) {
            ss << hex << setw(8) << setfill('0') << h[i];
        }
        
        // Reset hash values for next use
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        
        return ss.str();
    }
    
private:
    vector<uint8_t> pad(const string& input) {
        vector<uint8_t> padded(input.begin(), input.end());
        uint64_t bitLen = input.length() * 8;
        
        padded.push_back(0x80);
        
        while((padded.size() % 64) != 56) {
            padded.push_back(0x00);
        }
        
        for(int i = 7; i >= 0; i--) {
            padded.push_back((bitLen >> (i * 8)) & 0xFF);
        }
        
        return padded;
    }
    
    void processBlock(const uint8_t* block) {
        uint32_t w[64];
        
        for(int i = 0; i < 16; i++) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | 
                   (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }
        
        for(int i = 16; i < 64; i++) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }
        
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        
        for(int i = 0; i < 64; i++) {
            uint32_t t1 = hh + sig1(e) + ch(e, f, g) + k[i] + w[i];
            uint32_t t2 = sig0(a) + maj(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
};

// Block structure representing each node in the blockchain
class Block {
public:
    int index;
    time_t timestamp;
    string data;
    string previousHash;
    string hash;
    Block* next;

    Block(int idx, string blockData, string prevHash) {
        index = idx;
        timestamp = time(nullptr);
        data = blockData;
        previousHash = prevHash;
        hash = calculateHash();
        next = nullptr;
    }

    // Calculate SHA-256 hash for the block
    string calculateHash() {
        stringstream ss;
        ss << index << timestamp << data << previousHash;
        string input = ss.str();

        SHA256 sha256;
        return sha256.hash(input);
    }

    // Display block details
    void displayBlock() {
        cout << "\n========================================" << endl;
        cout << "Block #" << index << endl;
        cout << "========================================" << endl;
        cout << "Timestamp: " << ctime(&timestamp);
        cout << "Data: " << data << endl;
        cout << "Previous Hash: " << previousHash << endl;
        cout << "Hash: " << hash << endl;
        cout << "========================================\n" << endl;
    }
};

// Blockchain class using linked list
class Blockchain {
private:
    Block* head;
    Block* tail;
    int blockCount;

public:
    Blockchain() {
        head = nullptr;
        tail = nullptr;
        blockCount = 0;
        createGenesisBlock();
    }

    // Create the first block (Genesis Block)
    void createGenesisBlock() {
        Block* genesis = new Block(0, "Genesis Block", "0");
        head = genesis;
        tail = genesis;
        blockCount++;
        cout << "\n*** Genesis Block Created ***" << endl;
    }

    // Add a new block to the blockchain
    void addBlock(string data) {
        Block* newBlock = new Block(blockCount, data, tail->hash);
        tail->next = newBlock;
        tail = newBlock;
        blockCount++;
        cout << "\n*** Block #" << newBlock->index << " Added Successfully ***" << endl;
    }

    // Verify the integrity of the blockchain
    bool verifyChain() {
        Block* current = head;
        
        while(current != nullptr) {
            // Recalculate hash and compare
            string recalculatedHash = current->calculateHash();
            if(current->hash != recalculatedHash) {
                cout << "\n[ERROR] Block #" << current->index << " has been tampered with!" << endl;
                cout << "Expected Hash: " << recalculatedHash << endl;
                cout << "Current Hash: " << current->hash << endl;
                return false;
            }

            // Check if previous hash matches (except for genesis block)
            if(current->next != nullptr) {
                if(current->hash != current->next->previousHash) {
                    cout << "\n[ERROR] Chain broken between Block #" << current->index 
                         << " and Block #" << current->next->index << endl;
                    return false;
                }
            }

            current = current->next;
        }
        
        cout << "\n*** Blockchain is Valid! ***" << endl;
        return true;
    }

    // Display all blocks in the blockchain
    void displayChain() {
        cout << "\n\n********************************************" << endl;
        cout << "       COMPLETE BLOCKCHAIN" << endl;
        cout << "********************************************" << endl;
        cout << "Total Blocks: " << blockCount << endl;
        
        Block* current = head;
        while(current != nullptr) {
            current->displayBlock();
            current = current->next;
        }
    }

    // Modify block data (for testing integrity)
    void modifyBlockData(int blockIndex, string newData) {
        Block* current = head;
        
        while(current != nullptr) {
            if(current->index == blockIndex) {
                cout << "\n*** Modifying Block #" << blockIndex << " ***" << endl;
                cout << "Old Data: " << current->data << endl;
                current->data = newData;
                cout << "New Data: " << current->data << endl;
                cout << "\nNote: Hash NOT recalculated. Chain integrity compromised!" << endl;
                return;
            }
            current = current->next;
        }
        
        cout << "\n[ERROR] Block #" << blockIndex << " not found!" << endl;
    }

    // Destructor to free memory
    ~Blockchain() {
        Block* current = head;
        while(current != nullptr) {
            Block* temp = current;
            current = current->next;
            delete temp;
        }
    }
};

// Display menu
void displayMenu() {
    cout << "\n\n============================================" << endl;
    cout << "       BLOCKCHAIN MANAGEMENT SYSTEM" << endl;
    cout << "============================================" << endl;
    cout << "1. Add New Block" << endl;
    cout << "2. Display Blockchain" << endl;
    cout << "3. Verify Blockchain Integrity" << endl;
    cout << "4. Modify Block Data (Test Tampering)" << endl;
    cout << "5. Exit" << endl;
    cout << "============================================" << endl;
    cout << "Enter your choice: ";
}

int main() {
    Blockchain blockchain;
    int choice;
    string data;
    int blockIndex;

    while(true) {
        displayMenu();
        cin >> choice;
        cin.ignore(); // Clear newline from buffer

        switch(choice) {
            case 1:
                cout << "\nEnter data for new block: ";
                getline(cin, data);
                blockchain.addBlock(data);
                break;

            case 2:
                blockchain.displayChain();
                break;

            case 3:
                blockchain.verifyChain();
                break;

            case 4:
                cout << "\nEnter block index to modify: ";
                cin >> blockIndex;
                cin.ignore();
                cout << "Enter new data: ";
                getline(cin, data);
                blockchain.modifyBlockData(blockIndex, data);
                break;

            case 5:
                cout << "\n*** Exiting Blockchain System ***" << endl;
                return 0;

            default:
                cout << "\n[ERROR] Invalid choice! Please try again." << endl;
        }
    }

    return 0;
}