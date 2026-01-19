def verbose_elaphash(input_string: str) -> str:
    """
    A verbose version of the elaphash function that prints the state at each step.
    """
    # Helper to print byte arrays consistently
    def hex_print(data: bytearray, label: str, indent: str = "   ", max_len=64):
        hex_str = data.hex()
        if len(hex_str) > max_len * 2:
            hex_str = hex_str[:max_len*2] + "..."
        print(f"{indent}- {label}: {hex_str} (Length: {len(data)})")

    print(f"\n{'='*20} Elaphash Verbose Start: '{input_string}' {'='*20}\n")

    # Initial input manipulation remains the same
    print("1. Initial Input Manipulation")
    print(f"   - Original input: '{input_string}'")
    original_len = len(input_string)
    input_string = input_string + str(original_len)
    print(f"   - Appended length ('{original_len}'): '{input_string}'")
    input_string = input_string * 2
    print(f"   - Doubled string: '{input_string}'")

    current_bytes = bytearray(input_string, 'utf-8')
    hex_print(current_bytes, "Converted to bytes (UTF-8)")
    print("-" * 60)

    TARGET_BYTE_LENGTH = 32
    MAIN_ITERATIONS = 8

    # --- Verbose Helper Functions (no changes) ---
    def xor_byte_arrays(b1: bytearray, b2: bytearray) -> bytearray:
        len1, len2 = len(b1), len(b2)
        if len1 == 0 or len2 == 0: return bytearray()
        min_len = min(len1, len2)
        result = bytearray(min_len)
        for i in range(min_len):
            result[i] = b1[i] ^ b2[i]
        return result

    def perfect_shuffle_bytes(data: bytearray) -> bytearray:
        n = len(data)
        if n < 2: return data[:]
        mid = (n + 1) // 2
        first_half, second_half = data[:mid], data[mid:]
        shuffled = bytearray(n)
        idx_f, idx_s = 0, 0
        for i in range(n):
            if i % 2 == 0:
                if idx_f < len(first_half):
                    shuffled[i] = first_half[idx_f]; idx_f += 1
                elif idx_s < len(second_half):
                    shuffled[i] = second_half[idx_s]; idx_s += 1
            else:
                if idx_s < len(second_half):
                    shuffled[i] = second_half[idx_s]; idx_s += 1
                elif idx_f < len(first_half):
                    shuffled[i] = first_half[idx_f]; idx_f += 1
        return shuffled

    def verbose_diffuse_bytes(current_bytes: bytearray, forward: bool, round_num: int) -> bytearray:
        direction = 'Forward' if forward else 'Backward'
        print(f"      -> Executing {direction} Diffusion for Round {round_num}...")
        hex_print(current_bytes, "Input to diffusion", indent="         ")
        
        length = len(current_bytes)
        if length == 0: return current_bytes
        round_constant_base = round_num
        if length < 2:
            current_bytes[0] = (current_bytes[0] + round_constant_base + 0x1F + (0x7A if forward else 0xC3)) % 256
            hex_print(current_bytes, "Output (single byte case)", indent="         ")
            return current_bytes

        key_stream = current_bytes[:]
        candidate_shifts = [3, 7, 11, 17, 23] if forward else [5, 13, 19, 29]
        shift_amount = candidate_shifts[(round_num + length) % len(candidate_shifts)]
        shift_amount = shift_amount % length
        if shift_amount == 0: shift_amount = 1
        
        print(f"         - Key Stream Shift Amount: {shift_amount}")
        key_stream = (key_stream[shift_amount:] + key_stream[:shift_amount]) if forward \
                     else (key_stream[-shift_amount:] + key_stream[:-shift_amount])
        hex_print(key_stream, "Generated Key Stream", indent="         ")

        for i in range(length):
            current_bytes[i] ^= key_stream[i]
        hex_print(current_bytes, "State after XOR with Key Stream", indent="         ")

        for i in range(length):
            byte = current_bytes[i]
            byte = (byte + round_constant_base + i + 0x5A + (0x1B if forward else 0x3D)) & 0xFF
            rot_amount1 = ((i % 5) + 1) if forward else (((i+3) % 5) + 1)
            byte = ((byte >> rot_amount1) | (byte << (8 - rot_amount1))) & 0xFF
            xor_val = (round_constant_base * (0x3D if forward else 0x1B)) ^ (i * 0x73)
            byte = byte ^ (xor_val & 0xFF)
            multiplier = 0xAD if forward else 0xC5
            byte = (byte * multiplier) & 0xFF
            rot_amount2 = ((i + round_constant_base) % 5) + 2
            byte = ((byte << rot_amount2) | (byte >> (8 - rot_amount2))) & 0xFF
            current_bytes[i] = byte
        
        hex_print(current_bytes, "Final state after per-byte processing", indent="         ")
        return current_bytes

    def flip_inside_out(data: bytearray) -> bytearray:
        n = len(data)
        if n < 2: return data[:]
        mid = n // 2
        first_half, second_half = data[:mid], data[mid:]
        first_half.reverse()
        second_half.reverse()
        return first_half + second_half

    def rotate_right(data: bytearray, num_rotations: int = 1) -> bytearray:
        n = len(data)
        if n == 0: return data
        num_rotations %= n
        if num_rotations == 0: return data[:]
        return data[-num_rotations:] + data[:-num_rotations]

    def is_monochromatic(data: bytearray) -> bool:
        if not data or len(data) == 1: return False
        first_byte = data[0]
        return all(byte == first_byte for byte in data[1:])

    def break_homogeneity(data: bytearray, iteration_count: int) -> bytearray:
        if is_monochromatic(data):
            print("      - Homogeneity detected! Applying break logic.")
            hex_print(data, "Monochromatic input", indent="        ")
            length = len(data)
            base_offset = iteration_count * (length + 1) + (iteration_count ^ 0xAA)
            for i in range(length):
                data[i] = (data[i] + i + base_offset + (i*0x13)) % 256
            hex_print(data, "State after breaking", indent="        ")
        else:
            print("      - Data is not monochromatic. No change.")
        return data

    # --- Hashing Stages (Expansion, Compression, Normalization, Main Loop) ---
    if 0 < len(current_bytes) < TARGET_BYTE_LENGTH:
        print(f"2. Expansion Stage (Input too short, expanding to >= {TARGET_BYTE_LENGTH} bytes)")
        original_short_key_material = current_bytes[:]
        expansion_iter = 0
        while len(current_bytes) < TARGET_BYTE_LENGTH:
            expansion_iter += 1
            print(f"\n   -> Expansion Iteration {expansion_iter}")
            hex_print(current_bytes, "State before expansion")
            shuffled_current_state = perfect_shuffle_bytes(current_bytes[:])
            op1, op2 = shuffled_current_state, original_short_key_material
            max_len = max(len(op1), len(op2))
            padded_op1 = bytearray(op1[i % len(op1)] for i in range(max_len))
            padded_op2 = bytearray(op2[i % len(op2)] for i in range(max_len))
            part_to_append = xor_byte_arrays(padded_op1, padded_op2)
            hex_print(part_to_append, "Generated bytes to append")
            current_bytes.extend(part_to_append)
            hex_print(current_bytes, "State after appending")
            if len(current_bytes) > TARGET_BYTE_LENGTH * 4 and expansion_iter > 5:
                print("   - Expansion limit reached, breaking.")
                break
        print("-" * 60)
    if len(current_bytes) > TARGET_BYTE_LENGTH:
        print(f"3. Compression Stage (Input too long, compressing to {TARGET_BYTE_LENGTH} bytes)")
        compression_iter = 0
        while len(current_bytes) > TARGET_BYTE_LENGTH:
            compression_iter += 1
            print(f"\n   -> Compression Iteration {compression_iter}")
            hex_print(current_bytes, "State before compression")
            length = len(current_bytes)
            mid_point = length // 2
            half1, half2 = current_bytes[:mid_point], current_bytes[mid_point:]
            shuffled_half2 = perfect_shuffle_bytes(half2)
            reduced_bytes = bytearray(mid_point)
            len_shuffled_half2 = len(shuffled_half2)
            for i in range(mid_point):
                # =========================== BUG FIX START ===========================
                # ORIGINAL BUGGY LINE: reduced_bytes[i] = half1[i] ^ shuffled_half2[i % len_shuffled_half2]
                # This would result in all zeros if half1 and shuffled_half2 were identical (e.g., from a monochromatic input).
                #
                # THE FIX: We modify the byte from the shuffled half before XORing to break the symmetry.
                # Adding the index `i` and the `compression_iter` ensures the modifier is different for each byte and each compression round.
                modifier_byte = shuffled_half2[i % len_shuffled_half2]
                modified_byte = (modifier_byte + i + compression_iter) & 0xFF  # Use & 0xFF for fast modulo 256
                reduced_bytes[i] = half1[i] ^ modified_byte
                # ============================ BUG FIX END ============================

            # Update the label to reflect the fix
            hex_print(reduced_bytes, "Result (H1 ^ modified(S_H2))")
            current_bytes = reduced_bytes
        hex_print(current_bytes, "Final compressed state", indent="")
        print("-" * 60)
    print(f"4. Normalization to exactly {TARGET_BYTE_LENGTH} bytes")
    hex_print(current_bytes, "State before normalization")
    final_fixed_length_bytes = bytearray(TARGET_BYTE_LENGTH)
    if not current_bytes:
        print("   - Input is empty, creating a default seed.")
        for i in range(TARGET_BYTE_LENGTH):
            final_fixed_length_bytes[i] = (i ^ (TARGET_BYTE_LENGTH & 0xFF)) % 256
    elif len(current_bytes) > 0:
        print("   - Padding/truncating to target length by cycling.")
        for i in range(TARGET_BYTE_LENGTH):
            final_fixed_length_bytes[i] = current_bytes[i % len(current_bytes)]
    current_bytes = final_fixed_length_bytes
    hex_print(current_bytes, "Final normalized state")
    print("-" * 60)
    print("5. Initial State Scramble (XOR with shuffled self)")
    s1_initial = current_bytes[:]
    s2_shuffled_initial = perfect_shuffle_bytes(current_bytes[:])
    current_bytes = xor_byte_arrays(s1_initial, s2_shuffled_initial)
    hex_print(current_bytes, "Result (S1 ^ S2)")
    print("-" * 60)
    print(f"6. Main Hashing Loop ({MAIN_ITERATIONS} iterations)")
    for iteration_count in range(MAIN_ITERATIONS):
        round_num = iteration_count + 1
        print(f"\n{'─'*20} Iteration {round_num}/{MAIN_ITERATIONS} {'─'*20}")
        hex_print(current_bytes, "State at start of iteration", indent="  ")
        current_bytes = break_homogeneity(current_bytes, iteration_count)
        current_bytes = verbose_diffuse_bytes(current_bytes, forward=True, round_num=round_num)
        current_bytes = verbose_diffuse_bytes(current_bytes, forward=False, round_num=round_num)
        current_bytes = flip_inside_out(current_bytes)
        rot_amount = 1 + (iteration_count % 5)
        current_bytes = rotate_right(current_bytes, rot_amount)
        if iteration_count < MAIN_ITERATIONS - 1:
            s1_iter_loop = current_bytes[:]
            s2_permuted_iter_loop = bytearray()
            perm_type = iteration_count % 3
            if perm_type == 0: s2_permuted_iter_loop = perfect_shuffle_bytes(current_bytes[:])
            elif perm_type == 1:
                temp_perm = flip_inside_out(current_bytes[:])
                rot_val = (iteration_count // 2) + 1 + (len(current_bytes) // 11)
                s2_permuted_iter_loop = rotate_right(temp_perm, rot_val)
            else:
                temp_perm = perfect_shuffle_bytes(current_bytes[:])
                rot_val = (iteration_count // 3) + 1 + (len(current_bytes) // 7)
                s2_permuted_iter_loop = rotate_right(temp_perm, rot_val)
            current_bytes = xor_byte_arrays(s1_iter_loop, s2_permuted_iter_loop)
    print(f"\n{'─'*20} End of Main Loop {'─'*25}\n")
    print("7. Finalization")
    hex_print(current_bytes, "Final byte state before hex conversion")
    final_hash = current_bytes.hex()
    print(f"   - Final Hex Digest: {final_hash}")
    print(f"\n{'='*22} Elaphash Verbose End {'='*23}\n")
    return final_hash

if __name__ == '__main__':
    # 1. Ask the user for input.
    user_input = input("Please enter the text you want to hash: ")
    
    # 2. Run the hash function on the user's input.
    final_hash_result = verbose_elaphash(user_input)
    
    # 3. Print the final result again, clearly at the end.
    print("\n" + "*"*60)
    print(f"          Input: '{user_input}'")
    print(f"  Final Elaphash: {final_hash_result}")
    print("*"*60)
