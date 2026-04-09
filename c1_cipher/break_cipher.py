import hashlib
from typing import List, Tuple, Iterable, Optional

##### Given LFSR class

class LFSR:
    def __init__(self, feedback_taps, output_taps, seed):
        self.feedback_taps_i = feedback_taps
        self.output_taps_i = output_taps
        self.seed_i = seed

    def gen_stream(self, iters):
        state = self.seed_i[:]
        out_stream = [state[8]]

        for i in range(iters):
            feedback = 0
            for j, t in enumerate(self.feedback_taps_i):
                if t:
                    feedback ^= state[j]

            state = [feedback] + state[:-1]

            out_bit = 0
            for k, y in enumerate(self.output_taps_i):
                if y:
                    out_bit ^= state[k]

            out_stream.append(out_bit)

        return out_stream


#### Given type conversion functions

def bits_to_bytes(bits: List[int]) -> bytes:
    padded = [0] * ((8 - len(bits) % 8) % 8) + bits
    byte_array = bytearray()
    for i in range(0, len(padded), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | padded[i + j]
        byte_array.append(byte)
    return bytes(byte_array)


def bytes_to_bits(data: bytes) -> List[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def int_to_bits(n: int, width: int) -> List[int]:
    return [(n >> i) & 1 for i in range(width - 1, -1, -1)]


def text_to_binary_list(file_path: str) -> List[int]:
    binary_list = []
    with open(file_path, 'r', encoding='utf-8') as f:
        text = f.read()
    for char in text:
        binary_str = format(ord(char), '08b')
        binary_list.extend(int(bit) for bit in binary_str)
    return binary_list


def read_binary_list(file_path: str) -> List[int]:
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    return [int(ch) for ch in content if ch in '01']


def binary_list_to_text(binary_list: List[int]) -> str:
    chars = []
    for i in range(0, len(binary_list), 8):
        byte = binary_list[i:i+8]
        if len(byte) < 8:
            continue
        byte_str = ''.join(str(bit) for bit in byte)
        chars.append(chr(int(byte_str, 2)))
    return ''.join(chars)


def write_text(file_path: str, text: str) -> None:
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(text)


#### Given key hashing function 

def hash_key(key: bytes, iv: bytes, state_size: int) -> int:
    data = key + iv
    digest = hashlib.sha256(data).digest()
    state = int.from_bytes(digest, byteorder='big')
    mask = (1 << state_size) - 1
    state = state & mask
    if state == 0:
        state = 1
    return state



#### Bitmask helpers for fast search


# converts list of bits to an integer mask
def mask_from_bits(bits: List[int]) -> int:
    mask = 0
    for i, bit in enumerate(bits):
        if bit:
            mask |= (1 << i)
    return mask

def positions_in_mask(mask: int):
    pos = 0
    while mask:
        if mask & 1:
            yield pos
        mask >>= 1
        pos += 1


def generate_stream_mask(seed_bits: List[int], feedback_taps, output_taps, textlen: int) -> int:
    hashed_seed = int_to_bits(
        hash_key(bits_to_bytes(seed_bits), bits_to_bytes(IV), STATE_SIZE),
        STATE_SIZE,
    )
    stream = LFSR(feedback_taps, output_taps, hashed_seed).gen_stream(textlen)
    return mask_from_bits(stream[:textlen])

# for each possible nonzero seed, precompute the full stream mask 
# and which seeds produce a 1 or 0 at each position
def precompute_family(feedback_taps, output_taps, textlen: int):
    nseeds = (1 << STATE_SIZE) - 1
    all_seed_bits = (1 << nseeds) - 1

    stream_masks = []
    ones_by_pos = [0] * textlen
    zeros_by_pos = [0] * textlen

    for seed in range(1, nseeds + 1):
        seed_bits = int_to_bits(seed, STATE_SIZE)
        stream_mask = generate_stream_mask(seed_bits, feedback_taps, output_taps, textlen)
        stream_masks.append(stream_mask)

        seed_bit = 1 << (seed - 1)
        for pos in range(textlen):
            if (stream_mask >> pos) & 1:
                ones_by_pos[pos] |= seed_bit
            else:
                zeros_by_pos[pos] |= seed_bit

    return stream_masks, ones_by_pos, zeros_by_pos, all_seed_bits

# given a mask of required 1s, return bitset of seeds that produce 1s at all those positions
def seeds_with_required_ones(required_ones_mask: int, ones_by_pos: List[int], all_seed_bits: int) -> int:
    candidates = all_seed_bits
    for pos in positions_in_mask(required_ones_mask):
        candidates &= ones_by_pos[pos]
        if candidates == 0:
            return 0
    return candidates

# given a mask of required 1s and forbidden 1s, 
# return bitset of seeds that produce 1s at all required 
# positions and 0s at all forbidden positions
def seeds_with_required_ones_and_zeros(
    required_ones_mask: int,
    forbidden_ones_mask: int,
    ones_by_pos: List[int],
    zeros_by_pos: List[int],
    all_seed_bits: int,
) -> int:
    candidates = seeds_with_required_ones(required_ones_mask, ones_by_pos, all_seed_bits)
    if candidates == 0:
        return 0

    for pos in positions_in_mask(forbidden_ones_mask):
        candidates &= zeros_by_pos[pos]
        if candidates == 0:
            return 0

    return candidates


### Main attack 

IV = [0,1,0,0,1,0,1,1,0,1]
STATE_SIZE = 11

feedback_taps_0 = [0,0,0,0,0,0,0,0,1,0,1]
output_taps_0   = [1,0,0,0,0,0,1,0,0,0,1]

feedback_taps_1 = [0,1,0,1,0,0,0,0,0,0,1]
output_taps_1   = [1,0,0,0,0,1,0,1,0,0,1]

feedback_taps_2 = [0,0,1,0,0,1,0,0,1,0,1]
output_taps_2   = [1,1,0,0,0,0,0,1,0,0,1]


def main():
    ptext = text_to_binary_list("./input.txt")
    ctext = read_binary_list("./ctext.txt")

    if len(ptext) != len(ctext):
        raise ValueError(
            f"Plaintext/ciphertext length mismatch: {len(ptext)} vs {len(ctext)}"
        )

    textlen = len(ctext)

    # Known keystream from known plaintext/ciphertext pair.
    keystream_bits = [p ^ c for p, c in zip(ptext, ctext)]
    keystream_mask = mask_from_bits(keystream_bits)
    full_text_mask = (1 << textlen) - 1


    # using helper func, precomputes all candidate key streams
    s0_masks, ones0, zeroes0, all_s0 = precompute_family(feedback_taps_0, output_taps_0, textlen)
    s1_masks, ones1, zeros1, all_s1 = precompute_family(feedback_taps_1, output_taps_1, textlen)
    s2_masks, ones2, zeros2, all_s2 = precompute_family(feedback_taps_2, output_taps_2, textlen)



    for s0_seed in range(1, (1 << STATE_SIZE)):
        s0_mask = s0_masks[s0_seed - 1]

        # Since keystream = S0 XOR (S1 AND S2), the remaining target is S1 AND S2
        target_mask = keystream_mask ^ s0_mask

        # S1 must be 1 anywhere the target is 1
        cand1 = seeds_with_required_ones(target_mask, ones1, all_s1)
        if cand1 == 0:
            continue

        for s1_idx in positions_in_mask(cand1):
            s1_seed = s1_idx + 1
            s1_mask = s1_masks[s1_idx]

            # Where target is 0, any position with S1=1 forces S2=0.
            forbidden_ones_mask = s1_mask & (full_text_mask ^ target_mask)

            cand2 = seeds_with_required_ones_and_zeros(
                target_mask,
                forbidden_ones_mask,
                ones2,
                zeros2,
                all_s2,
            )
            if cand2 == 0:
                continue

            for s2_idx in positions_in_mask(cand2):
                s2_seed = s2_idx + 1
                s2_mask = s2_masks[s2_idx]

                recovered_keystream = s0_mask ^ (s1_mask & s2_mask)
                if recovered_keystream != keystream_mask:
                    continue

                recovered_bits = [
                    ctext[i] ^ ((recovered_keystream >> i) & 1)
                    for i in range(textlen)
                ]
                recovered_text = binary_list_to_text(recovered_bits)



                print("Found solution:")
                print("seed_0 =", s0_seed)
                print("seed_1 =", s1_seed)
                print("seed_2 =", s2_seed)
                print("plaintext =", recovered_text, "\n")

                write_text("./output.txt", recovered_text)
                print("Wrote recovered plaintext to output.txt")
                return

    print("No solution found.")


if __name__ == "__main__":
    main()