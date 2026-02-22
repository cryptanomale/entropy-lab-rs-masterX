/**
 * bench_linear.cl - Micro-benchmark for linear scan overhead
 */
__kernel void linear_lookup(
    __global const uchar* targets,
    const uint num_targets,
    __global const uchar* items,
    const uint item_len,
    const uint num_items,
    __global uchar* results
) {
    uint gid = get_global_id(0);
    if (gid >= num_items) return;

    __global const uchar* item = items + (gid * item_len);
    uchar found = 0;

    for (uint i = 0; i < num_targets; i++) {
        __global const uchar* target = targets + (i * item_len);
        bool match = true;
        for (uint j = 0; j < item_len; j++) {
            if (item[j] != target[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            found = 1;
            break;
        }
    }

    results[gid] = found;
}
