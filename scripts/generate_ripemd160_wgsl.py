#!/usr/bin/env python3
"""Generate correct RIPEMD160 transform for WGSL from OpenCL reference."""

# RIPEMD160 round specification from cl/ripemd.cl
# Each tuple: (vars, r_left, s_left, r_right, s_right)
rounds = [
    # Round 1: F1 left, F5 right, K=0x00000000, Kp=0x50A28BE6
    ("round1", "F1", "0x00000000u", "F5", "0x50a28be6u", [
        ("A,B,C,D,E", 0, 11, 5, 8),
        ("E,A,B,C,D", 1, 14, 14, 9),
        ("D,E,A,B,C", 2, 15, 7, 9),
        ("C,D,E,A,B", 3, 12, 0, 11),
        ("B,C,D,E,A", 4, 5, 9, 13),
        ("A,B,C,D,E", 5, 8, 2, 15),
        ("E,A,B,C,D", 6, 7, 11, 15),
        ("D,E,A,B,C", 7, 9, 4, 5),
        ("C,D,E,A,B", 8, 11, 13, 7),
        ("B,C,D,E,A", 9, 13, 6, 7),
        ("A,B,C,D,E", 10, 14, 15, 8),
        ("E,A,B,C,D", 11, 15, 8, 11),
        ("D,E,A,B,C", 12, 6, 1, 14),
        ("C,D,E,A,B", 13, 7, 10, 14),
        ("B,C,D,E,A", 14, 9, 3, 12),
        ("A,B,C,D,E", 15, 8, 12, 6),
    ]),
    # Round 2: F2 left, F4 right, K=0x5A827999, Kp=0x5C4DD124
    ("round2", "F2", "0x5a827999u", "F4", "0x5c4dd124u", [
        ("E,A,B,C,D", 7, 7, 6, 9),
        ("D,E,A,B,C", 4, 6, 11, 13),
        ("C,D,E,A,B", 13, 8, 3, 15),
        ("B,C,D,E,A", 1, 13, 7, 7),
        ("A,B,C,D,E", 10, 11, 0, 12),
        ("E,A,B,C,D", 6, 9, 13, 8),
        ("D,E,A,B,C", 15, 7, 5, 9),
        ("C,D,E,A,B", 3, 15, 10, 11),
        ("B,C,D,E,A", 12, 7, 14, 7),
        ("A,B,C,D,E", 0, 12, 15, 7),
        ("E,A,B,C,D", 9, 15, 8, 12),
        ("D,E,A,B,C", 5, 9, 12, 7),
        ("C,D,E,A,B", 2, 11, 4, 6),
        ("B,C,D,E,A", 14, 7, 9, 15),
        ("A,B,C,D,E", 11, 13, 1, 13),
        ("E,A,B,C,D", 8, 12, 2, 11),
    ]),
    # Round 3: F3 left, F3 right, K=0x6ED9EBA1, Kp=0x6D703EF3
    ("round3", "F3", "0x6ed9eba1u", "F3", "0x6d703ef3u", [
        ("D,E,A,B,C", 3, 11, 15, 9),
        ("C,D,E,A,B", 10, 13, 5, 7),
        ("B,C,D,E,A", 14, 6, 1, 15),
        ("A,B,C,D,E", 4, 7, 3, 11),
        ("E,A,B,C,D", 9, 14, 7, 8),
        ("D,E,A,B,C", 15, 9, 14, 6),
        ("C,D,E,A,B", 8, 13, 6, 6),
        ("B,C,D,E,A", 1, 15, 9, 14),
        ("A,B,C,D,E", 2, 14, 11, 12),
        ("E,A,B,C,D", 7, 8, 8, 13),
        ("D,E,A,B,C", 0, 13, 12, 5),
        ("C,D,E,A,B", 6, 6, 2, 14),
        ("B,C,D,E,A", 13, 5, 10, 13),
        ("A,B,C,D,E", 11, 12, 0, 13),
        ("E,A,B,C,D", 5, 7, 4, 7),
        ("D,E,A,B,C", 12, 5, 13, 5),
    ]),
    # Round 4: F4 left, F2 right, K=0x8F1BBCDC, Kp=0x7A6D76E9
    ("round4", "F4", "0x8f1bbcdcu", "F2", "0x7a6d76e9u", [
        ("C,D,E,A,B", 1, 11, 8, 15),
        ("B,C,D,E,A", 9, 12, 6, 5),
        ("A,B,C,D,E", 11, 14, 4, 8),
        ("E,A,B,C,D", 10, 15, 1, 11),
        ("D,E,A,B,C", 0, 14, 3, 14),
        ("C,D,E,A,B", 8, 15, 11, 14),
        ("B,C,D,E,A", 12, 9, 15, 6),
        ("A,B,C,D,E", 4, 8, 0, 14),
        ("E,A,B,C,D", 13, 9, 5, 6),
        ("D,E,A,B,C", 3, 14, 12, 9),
        ("C,D,E,A,B", 7, 5, 2, 12),
        ("B,C,D,E,A", 15, 6, 13, 9),
        ("A,B,C,D,E", 14, 8, 9, 12),
        ("E,A,B,C,D", 5, 6, 7, 5),
        ("D,E,A,B,C", 6, 5, 10, 15),
        ("C,D,E,A,B", 2, 12, 14, 8),
    ]),
    # Round 5: F5 left, F1 right, K=0xA953FD4E, Kp=0x00000000
    ("round5", "F5", "0xa953fd4eu", "F1", "0x00000000u", [
        ("B,C,D,E,A", 4, 9, 12, 8),
        ("A,B,C,D,E", 0, 15, 15, 5),
        ("E,A,B,C,D", 5, 5, 10, 12),
        ("D,E,A,B,C", 9, 11, 4, 9),
        ("C,D,E,A,B", 7, 6, 1, 12),
        ("B,C,D,E,A", 12, 8, 5, 5),
        ("A,B,C,D,E", 2, 13, 8, 14),
        ("E,A,B,C,D", 10, 12, 7, 6),
        ("D,E,A,B,C", 14, 5, 6, 8),
        ("C,D,E,A,B", 1, 12, 2, 13),
        ("B,C,D,E,A", 3, 13, 13, 6),
        ("A,B,C,D,E", 8, 14, 14, 5),
        ("E,A,B,C,D", 11, 11, 0, 15),
        ("D,E,A,B,C", 6, 8, 3, 13),
        ("C,D,E,A,B", 15, 5, 9, 11),
        ("B,C,D,E,A", 13, 6, 11, 11),
    ]),
]

# F functions for RIPEMD160
f_functions = {
    "F1": "(b ^ c ^ d)",
    "F2": "((b & c) | ((~b) & d))",
    "F3": "((b | (~c)) ^ d)",
    "F4": "((b & d) | (c & (~d)))",
    "F5": "(b ^ (c | (~d)))",
}

def generate_round(round_name, f_left, k_left, f_right, k_right, round_data):
    """Generate WGSL code for one round."""
    lines = [f"    // {round_name.capitalize()}: {f_left} left, {f_right} right"]

    for vars_str, r_left, s_left, r_right, s_right in round_data:
        # Parse variable order
        vars_list = vars_str.split(',')
        a, b, c, d, e = [v.lower() for v in vars_list]
        ap, bp, cp, dp, ep = [v.lower() + 'p' for v in vars_list]

        # Get function expressions - use placeholders to avoid cascading replacements
        def apply_func(func_expr, var_map):
            """Apply function with variable mapping using placeholders."""
            # First pass: replace with placeholders
            result = func_expr
            for old in var_map:
                result = result.replace(old, f'___{old}___')
            # Second pass: replace placeholders with actual values
            for old, new in var_map.items():
                result = result.replace(f'___{old}___', new)
            return result

        f_left_expr = apply_func(f_functions[f_left], {'b': b, 'c': c, 'd': d})
        f_right_expr = apply_func(f_functions[f_right], {'b': bp, 'c': cp, 'd': dp})

        # Generate left path
        left_line = f"    {a} += {f_left_expr} + block[{r_left}] + {k_left}; {a} = rol({a}, {s_left}u) + {e}; {c} = rol({c}, 10u);"
        lines.append(left_line)

        # Generate right path
        right_line = f"    {ap} += {f_right_expr} + block[{r_right}] + {k_right}; {ap} = rol({ap}, {s_right}u) + {ep}; {cp} = rol({cp}, 10u);"
        lines.append(right_line)

    return '\n'.join(lines)

# Generate complete function
print("fn ripemd160_transform(state: ptr<function, array<u32, 5>>, block: array<u32, 16>) {")
print("    var a = (*state)[0]; var b = (*state)[1]; var c = (*state)[2]; var d = (*state)[3]; var e = (*state)[4];")
print("    var ap = a; var bp = b; var cp = c; var dp = d; var ep = e;")
print()

for round_name, f_left, k_left, f_right, k_right, round_data in rounds:
    print(generate_round(round_name, f_left, k_left, f_right, k_right, round_data))
    print()

print("    let h0 = (*state)[0];")
print("    let h1 = (*state)[1];")
print("    let h2 = (*state)[2];")
print("    let h3 = (*state)[3];")
print("    let h4 = (*state)[4];")
print("    ")
print("    (*state)[0] = h1 + c + dp;")
print("    (*state)[1] = h2 + d + ep;")
print("    (*state)[2] = h3 + e + ap;")
print("    (*state)[3] = h4 + a + bp;")
print("    (*state)[4] = h0 + b + cp;")
print("}")
