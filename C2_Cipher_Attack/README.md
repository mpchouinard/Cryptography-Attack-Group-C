This project implements a SAT-based state recovery attack on an extended A5/1 stream cipher design using:

Verilog + Verilator (hardware simulation)
C++ (testbench interface)
Python + Z3 (SAT solver)

The goal is to recover the internal 64-bit state (and original key) from observed keystream bits.

Project Folder:
├── A51_EXT_STREAM.v # Verilog implementation of modified A5/1 cipher
├── RUN_NLFSR.cpp # Verilator C++ testbench (no SystemC)
├── sat_attack_c2.py # Python SAT-based state recovery attack
├── ks.txt # (Generated) keystream file

Requirements:
- Python 3.9+
- Z3 Solver
- Verilator
- C++ Compiler (clang/gcc)


Installations:
1. Homebrew: package manager for macOS (and Linux) that lets you install software from the terminal. (I Needed it to install verilator on python)

- /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
- echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
- brew --version

2. Install z3-solver
- pip install z3-solver

3. Install Verilator
- brew install verilator

4. Install C++ Compiler (I didn't need to but you might so I'll put it here just in case)
- xcode-select --install

Usage:

1. Compile the cipher:
verilator -Wall -Wno-fatal --cc A51_EXT_STREAM.v
--exe RUN_NLFSR.cpp --build -o sim

2. Generate Keystream
./obj_dir/sim <64-bit-key> --keystream 128 > ks.txt

3. Run SAT Attack
python sat_attack_c2.py --keystream ks.txt --bits 128
--verify-key <same-key>


How it works:

- The Verilog design is compiled using Verilator into a C++ simulation.
- The simulator generates keystream bits from a known key.
- The Python script:
    - Symbolically models the cipher using Boolean logic
    - Uses Z3 to solve for the internal state
- The recovered state is used to reconstruct the original key.