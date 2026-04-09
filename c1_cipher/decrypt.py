import hashlib

##############################
# LFSR module
##############################

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
                if (t):
                    feedback ^= state[j]
            
            state = [feedback] + state[:-1]

            out_bit = 0
            for k, y in enumerate(self.output_taps_i):
                if (y):
                    out_bit ^= state[k]

            out_stream.append(out_bit)

        return out_stream

##############################
# Type conversion functions
##############################

def bits_to_bytes(bits):
    padded = [0] * ((8 - len(bits) % 8) % 8) + bits

    byte_array = bytearray()
    for i in range(0, len(padded), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | padded[i + j]
        byte_array.append(byte)

    return bytes(byte_array)

def bytes_to_bits(data):
    bits = []
    
    for byte in data:
        for i in range(7, -1, -1):  # MSB → LSB
            bits.append((byte >> i) & 1)
    
    return bits

def int_to_bits(n, width):
    bits = []
    for i in range(width - 1, -1, -1):
        bits.append((n >> i) & 1)
    return bits

##############################
# Key has function with IV
##############################

def hash_key(key, iv, state_size):

    data = key + iv

    digest = hashlib.sha256(data).digest()

    state = int.from_bytes(digest, byteorder='big')

    mask = (1 << state_size) - 1
    state = state & mask

    if state == 0:
        state = 1

    return state

##############################
# File operations
##############################

def read_binary_list(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    binary_list = [int(ch) for ch in content if ch in '01']

    return binary_list

def binary_list_to_text(output_path, binary_list):
    chars = []

    for i in range(0, len(binary_list), 8):
        byte = binary_list[i:i+8]

        if len(byte) < 8:
            continue

        byte_str = ''.join(str(bit) for bit in byte)
        char = chr(int(byte_str, 2))
        chars.append(char)

    text = ''.join(chars)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(text)

##############################
# Main program flow
##############################

def main():

    ctext = read_binary_list("./ctext.txt")

    # Config values

    iv              = [0,1,0,0,1,0,1,1,0,1]

    feedback_taps_0 = [0,0,0,0,0,0,0,0,1,0,1]
    output_taps_0   = [1,0,0,0,0,0,1,0,0,0,1]
    seed_0          = [1,0,1,0,1,1,0,0,1,0,1]

    feedback_taps_1 = [0,1,0,1,0,0,0,0,0,0,1]
    output_taps_1   = [1,0,0,0,0,1,0,1,0,0,1]
    seed_1          = [0,1,1,1,1,0,1,0,0,1,1]

    feedback_taps_2 = [0,0,1,0,0,1,0,0,1,0,1]
    output_taps_2   = [1,1,0,0,0,0,0,1,0,0,1]
    seed_2          = [1,1,0,0,0,1,0,1,1,1,0]

    state_size      = len(feedback_taps_0)
    textlen         = len(ctext)

    # Generate LFSRs

    key_0   = int_to_bits(hash_key(bits_to_bytes(seed_0), bits_to_bytes(iv), state_size), state_size)
    LFSR_0  = LFSR(feedback_taps_0, output_taps_0, key_0)
    stream_0 = LFSR_0.gen_stream(textlen)

    key_1   = int_to_bits(hash_key(bits_to_bytes(seed_1), bits_to_bytes(iv), state_size), state_size)
    LFSR_1  = LFSR(feedback_taps_1, output_taps_1, key_1)
    stream_1 = LFSR_1.gen_stream(textlen)

    key_2   = int_to_bits(hash_key(bits_to_bytes(seed_2), bits_to_bytes(iv), state_size), state_size)
    LFSR_2  = LFSR(feedback_taps_2, output_taps_2, key_2)
    stream_2 = LFSR_2.gen_stream(textlen)

    ptext = []
    for i in range(textlen):
        ptext.append(ctext[i]^(stream_0[i] ^ (stream_1[i] & stream_2[i])))

    binary_list_to_text("./output.txt", ptext)

if __name__ == "__main__":
    main()