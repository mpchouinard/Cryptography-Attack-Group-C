// RUN_NLFSR.cpp — Verilator native C++ testbench (no SystemC)
#include <verilated.h>
#include "VA51_EXT_STREAM.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

void ERROR(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

uint8_t sbox[256];
void init_sbox() {
    uint8_t p = 1, q = 1;
    do {
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;
        uint8_t xformed = q ^ ROTL8(q,1) ^ ROTL8(q,2) ^ ROTL8(q,3) ^ ROTL8(q,4);
        sbox[p] = xformed ^ 0x63;
    } while (p != 1);
    sbox[0] = 0x63;
}

static VerilatedContext* ctx = nullptr;

static void pulse(VA51_EXT_STREAM* top) {
    top->clk = 0;
    top->eval();
    ctx->timeInc(100);
    top->clk = 1;
    top->eval();
    ctx->timeInc(100);
}

int main(int argc, char** argv) {
    int print_keystream = 0;
    if (argc == 4 && std::string(argv[2]) == "--keystream") {
        print_keystream = 1;
    } else if (argc < 4) {
        ERROR(
            "usage: <key-data (bin)> <input-file-path> <output-file-path>\n"
            "   OR: <key-data (bin)> --keystream <keystream-length (dec)>"
        );
    }

    init_sbox();

    ctx = new VerilatedContext;
    ctx->commandArgs(argc, argv);

    VA51_EXT_STREAM* top = new VA51_EXT_STREAM{ctx, "top"};

    top->clk           = 0;
    top->data_in       = 0;
    top->enable_setkey = 0;
    top->eval();

    long keylen = (long)strlen(argv[1]);
    if (keylen != 64) ERROR("Invalid key length — expected 64 binary characters!");

    top->enable_setkey = 1;
    for (int i = 0; i < 64; i++) {
        if      (argv[1][i] == '1') top->data_in = 1;
        else if (argv[1][i] == '0') top->data_in = 0;
        else ERROR("Unexpected character in key string — use only '0' and '1'");
        pulse(top);
    }
    top->enable_setkey = 0;
    top->data_in = 0;

    if (print_keystream) {
        int amt = std::stoi(std::string(argv[3]));
        for (int i = 0; i < amt; i++) {
            pulse(top);
            printf("%d", (int)top->sig_out);
        }
        printf("\n");
    } else {
        std::ifstream istrm(argv[2], std::ios::binary);
        if (!istrm.is_open()) ERROR("Failed to open plaintext file");

        std::ofstream ostrm(argv[3], std::ios::binary | std::ios::trunc);
        if (!ostrm.is_open()) ERROR("Failed to open ciphertext output file");

        char c;
        while (istrm.get(c)) {
            char o = 0;
            for (int i = 0; i < 8; i++) {
                pulse(top);
                int inp = (c & (1 << i)) != 0;
                int ks  = (int)top->sig_out;
                o |= (((ks ^ inp) & 1) << i);
            }
            ostrm.write(&o, 1);
        }
    }

    top->final();
    delete top;
    delete ctx;
    return 0;
}
