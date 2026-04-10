#!/usr/bin/env python3
"""
SAT-based State Recovery Attack on A5/1 Extended Stream Cipher (A51_EXT_STREAM)
================================================================================

Design Summary (from A51_EXT_STREAM.v):
  SR1: 19 bits  — polynomial x^19+x^18+x^17+x^14+1  — taps [18,17,16,13] — clock bit sr1[8]
  SR2: 22 bits  — polynomial x^22+x^21+1              — taps [21,20]       — clock bit sr2[10]
  SR3: 23 bits  — polynomial x^23+x^22+x^21+x^8+1    — taps [22,21,20,7]  — clock bit sr3[10]

  Clock majority: maj(sr1[8], sr2[10], sr3[10])
    A register clocks iff its clock bit equals the majority vote.

  Feedback equations:
    sr1_feedback = sr1[18] ^ sr1[17] ^ sr1[16] ^ sr1[13]
    sr2_feedback = sr2[21] ^ sr2[20]
    sr3_feedback = (sr3[22]^sr3[21]^sr3[20]^sr3[7]) ^ (sr1_feedback & sr2_feedback)

  Key loading (64 clock cycles with enable_setkey=1):
    Cycles  0-18  -> shift data_in into SR1  (sr1 = {sr1[17:0], data_in})
    Cycles 19-40  -> shift data_in into SR2
    Cycles 41-63  -> shift data_in into SR3

  IMPORTANT - output timing:
    sig_out is a combinational assign: sr1[18] ^ sr2[21] ^ sr3[22]
    The Verilator testbench reads sig_out AFTER eval() on the rising edge,
    so the observed bit reflects the state AFTER the registers have clocked.
    Therefore each keystream bit = output computed from the POST-clock state.

Requirements:
  pip install z3-solver
"""

import sys
import time
import argparse
from z3 import (
    Bool, BoolVal, And, Or, Not, Xor, If,
    Solver, sat, is_true
)


# ---------------------------------------------------------------------------
# Symbolic simulation
# ---------------------------------------------------------------------------

def majority(a, b, c):
    return Or(And(a, b), And(a, c), And(b, c))


def symbolic_clock(sr1, sr2, sr3):
    """
    Advance all three registers by one clock cycle symbolically.
    Returns (sr1_next, sr2_next, sr3_next).

    Register layout: index 0 = bit 0 (LSB/newest), index N-1 = MSB (oldest/output).
    Verilog shift: {sr[N-2:0], feedback}  =>  new bit enters at index 0,
                                               everything shifts up one position.
    In list terms: new = [feedback] + old[:-1]
    """
    # feedback taps read from pre-clock state
    sr1_fb = Xor(sr1[18], Xor(sr1[17], Xor(sr1[16], sr1[13])))
    sr2_fb = Xor(sr2[21], sr2[20])
    sr3_taps = Xor(sr3[22], Xor(sr3[21], Xor(sr3[20], sr3[7])))
    sr3_fb = Xor(sr3_taps, And(sr1_fb, sr2_fb))

    maj = majority(sr1[8], sr2[10], sr3[10])

    def cond_shift(reg, fb, clk_bit):
        shifted = [fb] + reg[:-1]
        return [If(clk_bit == maj, shifted[i], reg[i]) for i in range(len(reg))]

    sr1_next = cond_shift(sr1, sr1_fb, sr1[8])
    sr2_next = cond_shift(sr2, sr2_fb, sr2[10])
    sr3_next = cond_shift(sr3, sr3_fb, sr3[10])

    return sr1_next, sr2_next, sr3_next


def symbolic_output(sr1, sr2, sr3):
    """Output bit from the current (post-clock) state."""
    return Xor(sr1[18], Xor(sr2[21], sr3[22]))


def symbolic_initial_state():
    sr1 = [Bool(f"sr1_{i}") for i in range(19)]
    sr2 = [Bool(f"sr2_{i}") for i in range(22)]
    sr3 = [Bool(f"sr3_{i}") for i in range(23)]
    return sr1, sr2, sr3


# ---------------------------------------------------------------------------
# Concrete simulation (mirrors Verilog exactly, for verification)
# ---------------------------------------------------------------------------

def concrete_clock(sr1, sr2, sr3):
    """
    One concrete clock step. Returns (sr1_next, sr2_next, sr3_next, out_bit).
    out_bit is read from the POST-clock state (matching Verilator testbench).
    """
    sr1_fb = sr1[18] ^ sr1[17] ^ sr1[16] ^ sr1[13]
    sr2_fb = sr2[21] ^ sr2[20]
    sr3_taps = sr3[22] ^ sr3[21] ^ sr3[20] ^ sr3[7]
    sr3_fb = sr3_taps ^ (sr1_fb & sr2_fb)

    maj = (sr1[8] & sr2[10]) | (sr1[8] & sr3[10]) | (sr2[10] & sr3[10])

    # new bit enters at index 0, everything shifts up
    if sr1[8] == maj:
        sr1 = [sr1_fb] + sr1[:-1]
    if sr2[10] == maj:
        sr2 = [sr2_fb] + sr2[:-1]
    if sr3[10] == maj:
        sr3 = [sr3_fb] + sr3[:-1]

    # output read AFTER clock
    out = sr1[18] ^ sr2[21] ^ sr3[22]

    return sr1, sr2, sr3, out


def load_key_concrete(key_bits):
    """
    Simulate 64 key-loading cycles. key_bits[0] is the first bit sent.
    Verilog: {sr[N-2:0], data_in} => new bit enters at index 0.
    """
    sr1 = [0] * 19
    sr2 = [0] * 22
    sr3 = [0] * 23
    for cycle, bit in enumerate(key_bits):
        b = int(bit)
        if cycle < 19:
            sr1 = [b] + sr1[:-1]
        elif cycle < 41:
            sr2 = [b] + sr2[:-1]
        else:
            sr3 = [b] + sr3[:-1]
    return sr1, sr2, sr3


def generate_keystream_concrete(sr1, sr2, sr3, n):
    sr1, sr2, sr3 = list(sr1), list(sr2), list(sr3)
    ks = []
    for _ in range(n):
        sr1, sr2, sr3, bit = concrete_clock(sr1, sr2, sr3)
        ks.append(bit)
    return ks


# ---------------------------------------------------------------------------
# Self-consistency check
# ---------------------------------------------------------------------------

def self_check(key_str, observed_ks):
    """
    Verify that the concrete Python model reproduces the hardware keystream.
    This must pass before the SAT attack can possibly succeed.
    """
    key_bits = [int(c) for c in key_str]
    sr1, sr2, sr3 = load_key_concrete(key_bits)
    python_ks = generate_keystream_concrete(sr1, sr2, sr3, len(observed_ks))

    mismatches = sum(a != b for a, b in zip(python_ks, observed_ks))
    print(f"[*] Self-check: Python model vs hardware keystream")
    print(f"    Hardware : {''.join(str(b) for b in observed_ks[:32])}...")
    print(f"    Python   : {''.join(str(b) for b in python_ks[:32])}...")
    if mismatches == 0:
        print(f"[+] Self-check PASSED — Python model matches hardware exactly.\n")
        return True
    else:
        print(f"[-] Self-check FAILED — {mismatches}/{len(observed_ks)} bits differ.")
        print(f"    The SAT attack cannot succeed if the model does not match hardware.\n")
        return False


# ---------------------------------------------------------------------------
# SAT Attack
# ---------------------------------------------------------------------------

def sat_attack(keystream_bits, verbose=True):
    """
    Recover post-key-load internal state from observed keystream bits.
    Clock first, then read output — matching Verilator testbench behaviour.
    """
    if verbose:
        print(f"[*] SAT attack started — using {len(keystream_bits)} keystream bits")
        print(f"[*] State space: 2^64 = {2**64:.2e} possible initial states")
        print(f"[*] Building symbolic circuit...\n")

    t0 = time.time()
    solver = Solver()

    sr1, sr2, sr3 = symbolic_initial_state()

    for step, observed_bit in enumerate(keystream_bits):
        # Clock first, then constrain the post-clock output
        sr1, sr2, sr3 = symbolic_clock(sr1, sr2, sr3)
        out_sym = symbolic_output(sr1, sr2, sr3)

        if observed_bit == 1:
            solver.add(out_sym)
        else:
            solver.add(Not(out_sym))

        if verbose and (step + 1) % 10 == 0:
            print(f"  [+] Added {step + 1} keystream constraints...")

    if verbose:
        elapsed = time.time() - t0
        print(f"\n[*] Circuit unrolled in {elapsed:.2f}s — invoking SAT solver...\n")

    t1 = time.time()
    result = solver.check()
    solve_time = time.time() - t1

    if result == sat:
        model = solver.model()
        sr1_val = [1 if is_true(model[Bool(f"sr1_{i}")]) else 0 for i in range(19)]
        sr2_val = [1 if is_true(model[Bool(f"sr2_{i}")]) else 0 for i in range(22)]
        sr3_val = [1 if is_true(model[Bool(f"sr3_{i}")]) else 0 for i in range(23)]

        if verbose:
            print(f"[+] SAT: solution found in {solve_time:.2f}s")
            print(f"\n    SR1 (19 bits): {''.join(str(b) for b in sr1_val)}")
            print(f"    SR2 (22 bits): {''.join(str(b) for b in sr2_val)}")
            print(f"    SR3 (23 bits): {''.join(str(b) for b in sr3_val)}")

        return {"sr1": sr1_val, "sr2": sr2_val, "sr3": sr3_val}
    else:
        if verbose:
            print(f"[-] UNSAT after {solve_time:.2f}s — no solution found.")
            print("    Run with --verify-key to confirm self-check passes.")
        return None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_recovery(recovered_state, keystream_bits, verbose=True):
    sr1 = list(recovered_state["sr1"])
    sr2 = list(recovered_state["sr2"])
    sr3 = list(recovered_state["sr3"])
    reproduced = generate_keystream_concrete(sr1, sr2, sr3, len(keystream_bits))
    mismatches = sum(a != b for a, b in zip(reproduced, keystream_bits))
    if verbose:
        print(f"\n[*] Verification: reproduced {len(keystream_bits)} keystream bits")
        if mismatches == 0:
            print(f"[+] All {len(keystream_bits)} bits match — state recovery SUCCESSFUL!")
        else:
            print(f"[-] {mismatches} mismatches — state recovery FAILED.")
    return mismatches == 0


def state_to_key(recovered_state):
    """
    Reverse the key-loading shift to recover the original 64-bit key string.
    Last bit sent is at index 0; first bit sent is at index N-1.
    SR1 (19 bits): key[0..18], sr1[0]=key[18], sr1[18]=key[0]
    SR2 (22 bits): key[19..40], sr2[0]=key[40], sr2[21]=key[19]
    SR3 (23 bits): key[41..63], sr3[0]=key[63], sr3[22]=key[41]
    """
    sr1 = recovered_state["sr1"]
    sr2 = recovered_state["sr2"]
    sr3 = recovered_state["sr3"]
    key = [0] * 64
    for i in range(19):
        key[18 - i] = sr1[i]
    for i in range(22):
        key[40 - i] = sr2[i]
    for i in range(23):
        key[63 - i] = sr3[i]
    return "".join(str(b) for b in key)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def run_demo():
    print("=" * 65)
    print("  A5/1-EXT SAT State Recovery Attack — Demo")
    print("=" * 65)

    known_key_str = "1011001101001110100111000101101001001100101011100001110100101101"
    key_bits = [int(c) for c in known_key_str]
    print(f"\n[*] Known key (64 bits): {known_key_str}")

    sr1_init, sr2_init, sr3_init = load_key_concrete(key_bits)
    print(f"    SR1 after load: {''.join(str(b) for b in sr1_init)}")
    print(f"    SR2 after load: {''.join(str(b) for b in sr2_init)}")
    print(f"    SR3 after load: {''.join(str(b) for b in sr3_init)}")

    N_BITS = 64
    ks = generate_keystream_concrete(sr1_init, sr2_init, sr3_init, N_BITS)
    print(f"\n[*] Generated {N_BITS} keystream bits (from Python model):")
    print(f"    {''.join(str(b) for b in ks)}\n")

    recovered = sat_attack(ks, verbose=True)

    if recovered:
        verify_recovery(recovered, ks, verbose=True)
        recovered_key = state_to_key(recovered)
        print(f"\n[*] Recovered key : {recovered_key}")
        print(f"    Original  key  : {known_key_str}")
        if recovered_key == known_key_str:
            print("[+] Key strings match exactly!")
        else:
            print("[!] Aliased state — try more bits to disambiguate.")

    print("\n" + "=" * 65)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="SAT-based state recovery attack on A5/1-EXT stream cipher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sat_attack_a51_ext.py --demo
  python sat_attack_a51_ext.py --keystream ks.txt --bits 64 --verify-key <64-bit-key>
        """
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run built-in self-consistent demo")
    parser.add_argument("--keystream", type=str,
                        help="Path to keystream file (ASCII 0/1 chars)")
    parser.add_argument("--bits", type=int, default=64,
                        help="Number of keystream bits to use (default: 64)")
    parser.add_argument("--verify-key", type=str,
                        help="64-bit binary key — runs self-check before attack")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.demo:
        run_demo()
        return

    if not args.keystream:
        print("Usage: python sat_attack_a51_ext.py --demo")
        print("       python sat_attack_a51_ext.py --keystream <file> [--bits N] [--verify-key <key>]")
        sys.exit(1)

    with open(args.keystream) as f:
        raw = f.read().strip()
    ks_bits = [int(c) for c in raw if c in "01"]

    if len(ks_bits) < args.bits:
        print(f"[!] Only {len(ks_bits)} bits in file, using all.")
        args.bits = len(ks_bits)
    ks_bits = ks_bits[:args.bits]

    print("=" * 65)
    print("  A5/1-EXT SAT State Recovery Attack")
    print("=" * 65)
    print(f"\n[*] Using {args.bits} keystream bits from '{args.keystream}'")

    # Self-check first — confirms Python model matches hardware before wasting solver time
    if args.verify_key:
        ok = self_check(args.verify_key, ks_bits)
        if not ok:
            print("[!] Aborting — fix the model before running the SAT attack.")
            sys.exit(1)

    recovered = sat_attack(ks_bits, verbose=True)

    if recovered:
        verify_recovery(recovered, ks_bits, verbose=True)
        if args.verify_key:
            recovered_key = state_to_key(recovered)
            print(f"\n[*] Recovered key : {recovered_key}")
            print(f"    Provided  key  : {args.verify_key}")
            match = (recovered_key == args.verify_key)
            print(f"[{'+'if match else '!'}] Keys {'match' if match else 'differ (aliased state — try more bits)'}.")

    print()


if __name__ == "__main__":
    main()