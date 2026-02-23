// randstorm_full.wgsl — naga/wgpu-22 safe
// No dynamic array indexing. No nested functions. No loops over local arrays.
// U256 = {hi:vec4<u32>, lo:vec4<u32>}  (hi.x=MSW, lo.w=LSW)

const TIMESTAMPS_PER_THREAD:u32=4u;
const RESULT_STRIDE:u32=14u;

const P0:u32=0xFFFFFFFFu;const P1:u32=0xFFFFFFFFu;
const P2:u32=0xFFFFFFFFu;const P3:u32=0xFFFFFFFFu;
const P4:u32=0xFFFFFFFFu;const P5:u32=0xFFFFFFFFu;
const P6:u32=0xFFFFFFFEu;const P7:u32=0xFFFFFC2Fu;
const P_INV:u32=0xD2253531u;
const R2_0:u32=0x00000000u;const R2_1:u32=0x00000000u;
const R2_2:u32=0x00000000u;const R2_3:u32=0x00000001u;
const R2_4:u32=0x000007A2u;const R2_5:u32=0x000E90A1u;
const R2_6:u32=0x0000E2EEu;const R2_7:u32=0xA9BC4E9Du;
const MON1_6:u32=0x00000001u;const MON1_7:u32=0x000003D1u;
const GXM0:u32=0x9981E643u;const GXM1:u32=0xE9089F48u;
const GXM2:u32=0x979F48C0u;const GXM3:u32=0x33A3D4E5u;
const GXM4:u32=0x58B0573Du;const GXM5:u32=0x0C5E5B10u;
const GXM6:u32=0xCB936E2Eu;const GXM7:u32=0x4D87C565u;
const GYM0:u32=0xF9308A01u;const GYM1:u32=0x9258C310u;
const GYM2:u32=0x49344F85u;const GYM3:u32=0xF05D8579u;
const GYM4:u32=0x2A6F2CF3u;const GYM5:u32=0x5160F3EFu;
const GYM6:u32=0x3E3EA8EBu;const GYM7:u32=0x0B5EA0AFu;

struct Fingerprint{timestamp_lo:u32,timestamp_hi:u32,screen_width:u32,screen_height:u32};
@group(0)@binding(0) var<storage,read>       fingerprints:array<Fingerprint>;
@group(0)@binding(1) var<storage,read>       bloom_filter:array<u32>;
@group(0)@binding(2) var<storage,read_write> results:array<u32>;
@group(0)@binding(3) var<storage,read_write> arc4_state:array<u32>;

struct U256{hi:vec4<u32>,lo:vec4<u32>};
fn u256z()->U256{return U256(vec4<u32>(0u),vec4<u32>(0u));}
fn u256w(a:u32,b:u32,c:u32,d:u32,e:u32,f:u32,g:u32,h:u32)->U256{
    return U256(vec4<u32>(a,b,c,d),vec4<u32>(e,f,g,h));}
fn u256_is_zero(a:U256)->bool{
    return all(a.hi==vec4<u32>(0u))&&all(a.lo==vec4<u32>(0u));}
fn gw(a:U256,i:u32)->u32{
    if(i==0u){return a.hi.x;}if(i==1u){return a.hi.y;}
    if(i==2u){return a.hi.z;}if(i==3u){return a.hi.w;}
    if(i==4u){return a.lo.x;}if(i==5u){return a.lo.y;}
    if(i==6u){return a.lo.z;}return a.lo.w;}
fn sw(a:ptr<function,U256>,i:u32,v:u32){
    if(i==0u){(*a).hi.x=v;return;}if(i==1u){(*a).hi.y=v;return;}
    if(i==2u){(*a).hi.z=v;return;}if(i==3u){(*a).hi.w=v;return;}
    if(i==4u){(*a).lo.x=v;return;}if(i==5u){(*a).lo.y=v;return;}
    if(i==6u){(*a).lo.z=v;return;}(*a).lo.w=v;}
fn u256_gte(a:U256,b:U256)->bool{
    if(a.hi.x!=b.hi.x){return a.hi.x>b.hi.x;}if(a.hi.y!=b.hi.y){return a.hi.y>b.hi.y;}
    if(a.hi.z!=b.hi.z){return a.hi.z>b.hi.z;}if(a.hi.w!=b.hi.w){return a.hi.w>b.hi.w;}
    if(a.lo.x!=b.lo.x){return a.lo.x>b.lo.x;}if(a.lo.y!=b.lo.y){return a.lo.y>b.lo.y;}
    if(a.lo.z!=b.lo.z){return a.lo.z>b.lo.z;}if(a.lo.w!=b.lo.w){return a.lo.w>b.lo.w;}
    return true;}
fn u256_add(a:U256,b:U256)->U256{
    var r:U256;var c:u32=0u;var s:u32;var c1:u32;var c2:u32;
    s=a.lo.w+b.lo.w;c1=select(0u,1u,s<a.lo.w);s+=c;c2=select(0u,1u,s<c);r.lo.w=s;c=c1|c2;
    s=a.lo.z+b.lo.z;c1=select(0u,1u,s<a.lo.z);s+=c;c2=select(0u,1u,s<c);r.lo.z=s;c=c1|c2;
    s=a.lo.y+b.lo.y;c1=select(0u,1u,s<a.lo.y);s+=c;c2=select(0u,1u,s<c);r.lo.y=s;c=c1|c2;
    s=a.lo.x+b.lo.x;c1=select(0u,1u,s<a.lo.x);s+=c;c2=select(0u,1u,s<c);r.lo.x=s;c=c1|c2;
    s=a.hi.w+b.hi.w;c1=select(0u,1u,s<a.hi.w);s+=c;c2=select(0u,1u,s<c);r.hi.w=s;c=c1|c2;
    s=a.hi.z+b.hi.z;c1=select(0u,1u,s<a.hi.z);s+=c;c2=select(0u,1u,s<c);r.hi.z=s;c=c1|c2;
    s=a.hi.y+b.hi.y;c1=select(0u,1u,s<a.hi.y);s+=c;c2=select(0u,1u,s<c);r.hi.y=s;c=c1|c2;
    s=a.hi.x+b.hi.x;c1=select(0u,1u,s<a.hi.x);s+=c;c2=select(0u,1u,s<c);r.hi.x=s;return r;}
fn u256_sub(a:U256,b:U256)->U256{
    var r:U256;var bw:u32=0u;var d:u32;var b1:u32;var b2:u32;var prev:u32;
    prev=a.lo.w-b.lo.w;b1=select(0u,1u,a.lo.w<b.lo.w);d=prev-bw;b2=select(0u,1u,prev<bw);r.lo.w=d;bw=b1|b2;
    prev=a.lo.z-b.lo.z;b1=select(0u,1u,a.lo.z<b.lo.z);d=prev-bw;b2=select(0u,1u,prev<bw);r.lo.z=d;bw=b1|b2;
    prev=a.lo.y-b.lo.y;b1=select(0u,1u,a.lo.y<b.lo.y);d=prev-bw;b2=select(0u,1u,prev<bw);r.lo.y=d;bw=b1|b2;
    prev=a.lo.x-b.lo.x;b1=select(0u,1u,a.lo.x<b.lo.x);d=prev-bw;b2=select(0u,1u,prev<bw);r.lo.x=d;bw=b1|b2;
    prev=a.hi.w-b.hi.w;b1=select(0u,1u,a.hi.w<b.hi.w);d=prev-bw;b2=select(0u,1u,prev<bw);r.hi.w=d;bw=b1|b2;
    prev=a.hi.z-b.hi.z;b1=select(0u,1u,a.hi.z<b.hi.z);d=prev-bw;b2=select(0u,1u,prev<bw);r.hi.z=d;bw=b1|b2;
    prev=a.hi.y-b.hi.y;b1=select(0u,1u,a.hi.y<b.hi.y);d=prev-bw;b2=select(0u,1u,prev<bw);r.hi.y=d;bw=b1|b2;
    prev=a.hi.x-b.hi.x;b1=select(0u,1u,a.hi.x<b.hi.x);d=prev-bw;b2=select(0u,1u,prev<bw);r.hi.x=d;return r;}
fn mul_hi(a:u32,b:u32)->u32{
    let al=a&0xFFFFu;let ah=a>>16u;let bl=b&0xFFFFu;let bh=b>>16u;
    let mid=al*bh+ah*bl;
    return ah*bh+(mid>>16u)+(((al*bl)>>16u)+(mid&0xFFFFu))>>16u;}
fn fp_p()->U256{return u256w(P0,P1,P2,P3,P4,P5,P6,P7);}
fn fp_add(a:U256,b:U256)->U256{var r=u256_add(a,b);if(u256_gte(r,fp_p())){r=u256_sub(r,fp_p());}return r;}
fn fp_sub(a:U256,b:U256)->U256{if(u256_gte(a,b)){return u256_sub(a,b);}return u256_sub(u256_add(a,fp_p()),b);}
fn fp_dbl(a:U256)->U256{return fp_add(a,a);}
fn fp_mont1()->U256{return u256w(0u,0u,0u,0u,0u,0u,MON1_6,MON1_7);}
fn fp_r2()->U256{return u256w(R2_0,R2_1,R2_2,R2_3,R2_4,R2_5,R2_6,R2_7);}
fn mont_mul(a:U256,b:U256)->U256{
    var thi:vec4<u32>=vec4<u32>(0u);var tlo:vec4<u32>=vec4<u32>(0u);var te:u32=0u;
    let p=fp_p();
    for(var i=0u;i<8u;i++){
        let ai=gw(a,7u-i);var c:u32=0u;
        {let bj=gw(b,7u);let lo=ai*bj;let hi=mul_hi(ai,bj);let s1=thi.x+lo;let c1=select(0u,1u,s1<thi.x);let s2=s1+c;let c2=select(0u,1u,s2<c);thi.x=s2;c=hi+c1+c2;}
        {let bj=gw(b,6u);let lo=ai*bj;let hi=mul_hi(ai,bj);let s1=thi.y+lo;let c1=select(0u,1u,s1<thi.y);let s2=s1+c;let c2=select(0u,1u,s2<c);thi.y=s2;c=hi+c1+c2;}
        {let bj=gw(b,5u);let lo=ai*bj;let hi=mul_hi(ai,bj);let s1=thi.z+lo;let c1=select(0u,1u,s1<thi.z);let s2=s1+c;let c2=select(0u,1u,s2<c);thi.z=s2;c=hi+c1+c2;}
        {let bj=gw(b,4u);let lo=ai*bj;let hi=mul_hi(ai,bj);let s1=thi.w+lo;let c1=select(0u,1u,s1<thi.w);let s2=s1+c;let c2=select(0u,1u,s2<c);thi.w=s2;c=hi+c1+c2;}
        {let bj=gw(b,3u);let lo=ai*bj;let hi=mul_hi(ai,bj);let s1=tlo.x+lo;let c1=select(0u,1u,s1<tlo.x);let s2=s1+c;let c2=select(0u,1u,s2<c);tlo.x=s2;c=hi+c1+c2;}
        {let bj=gw(b,2u);let lo=ai*bj;let hi=mul_hi(ai,bj);let s1=tlo.y+lo;let c1=select(0u,1u,s1<tlo.y);let s2=s1+c;let c2=select(0u,1u,s2<c);tlo.y=s2;c=hi+c1+c2;}
        {let bj=gw(b,1u);let lo=ai*bj;let hi=mul_hi(ai,bj);let s1=tlo.z+lo;let c1=select(0u,1u,s1<tlo.z);let s2=s1+c;let c2=select(0u,1u,s2<c);tlo.z=s2;c=hi+c1+c2;}
        {let bj=gw(b,0u);let lo=ai*bj;let hi=mul_hi(ai,bj);let s1=tlo.w+lo;let c1=select(0u,1u,s1<tlo.w);let s2=s1+c;let c2=select(0u,1u,s2<c);tlo.w=s2;c=hi+c1+c2;}
        te+=c;
        let m=thi.x*P_INV;var c2:u32=0u;
        {let pj=gw(p,7u);let lo=m*pj;let hi=mul_hi(m,pj);let s1=thi.x+lo;let c1=select(0u,1u,s1<thi.x);let s2=s1+c2;let cx=select(0u,1u,s2<c2);c2=hi+c1+cx;}
        {let pj=gw(p,6u);let lo=m*pj;let hi=mul_hi(m,pj);let s1=thi.y+lo;let c1=select(0u,1u,s1<thi.y);let s2=s1+c2;let cx=select(0u,1u,s2<c2);thi.x=s2;c2=hi+c1+cx;}
        {let pj=gw(p,5u);let lo=m*pj;let hi=mul_hi(m,pj);let s1=thi.z+lo;let c1=select(0u,1u,s1<thi.z);let s2=s1+c2;let cx=select(0u,1u,s2<c2);thi.y=s2;c2=hi+c1+cx;}
        {let pj=gw(p,4u);let lo=m*pj;let hi=mul_hi(m,pj);let s1=thi.w+lo;let c1=select(0u,1u,s1<thi.w);let s2=s1+c2;let cx=select(0u,1u,s2<c2);thi.z=s2;c2=hi+c1+cx;}
        {let pj=gw(p,3u);let lo=m*pj;let hi=mul_hi(m,pj);let s1=tlo.x+lo;let c1=select(0u,1u,s1<tlo.x);let s2=s1+c2;let cx=select(0u,1u,s2<c2);thi.w=s2;c2=hi+c1+cx;}
        {let pj=gw(p,2u);let lo=m*pj;let hi=mul_hi(m,pj);let s1=tlo.y+lo;let c1=select(0u,1u,s1<tlo.y);let s2=s1+c2;let cx=select(0u,1u,s2<c2);tlo.x=s2;c2=hi+c1+cx;}
        {let pj=gw(p,1u);let lo=m*pj;let hi=mul_hi(m,pj);let s1=tlo.z+lo;let c1=select(0u,1u,s1<tlo.z);let s2=s1+c2;let cx=select(0u,1u,s2<c2);tlo.y=s2;c2=hi+c1+cx;}
        {let pj=gw(p,0u);let lo=m*pj;let hi=mul_hi(m,pj);let s1=tlo.w+lo;let c1=select(0u,1u,s1<tlo.w);let s2=s1+c2;let cx=select(0u,1u,s2<c2);tlo.z=s2;c2=hi+c1+cx;}
        tlo.w=te+c2;te=0u;
    }
    var r=u256w(thi.x,thi.y,thi.z,thi.w,tlo.x,tlo.y,tlo.z,tlo.w);
    if(u256_gte(r,fp_p())){r=u256_sub(r,fp_p());}return r;}
fn fp_mul(a:U256,b:U256)->U256{return mont_mul(a,b);}
fn fp_sqr(a:U256)->U256{return mont_mul(a,a);}
fn from_mont(a:U256)->U256{var one=u256z();one.lo.w=1u;return mont_mul(a,one);}
fn fp_inv(a:U256)->U256{
    var e=fp_p();e.lo.w=0xFFFFFC2Du;
    var res=fp_mont1();var base=a;var i:i32=255;
    loop{if(i<0){break;}
        let wi=u32(i)/32u;let bi=u32(i)%32u;
        let bit=(gw(e,7u-wi)>>bi)&1u;
        if(bit==1u){res=fp_mul(res,base);}
        base=fp_sqr(base);i-=1;}
    return res;}
struct JacPt{x:U256,y:U256,z:U256};
fn jac_inf()->JacPt{return JacPt(fp_mont1(),fp_mont1(),u256z());}
fn jac_is_inf(p:JacPt)->bool{return u256_is_zero(p.z);}
fn jac_dbl(p:JacPt)->JacPt{
    if(jac_is_inf(p)){return p;}
    let X1=p.x;let Y1=p.y;let Z1=p.z;
    let A=fp_sqr(X1);let B=fp_sqr(Y1);let C=fp_sqr(B);
    let D=fp_dbl(fp_sub(fp_sub(fp_sqr(fp_add(X1,B)),A),C));
    let E=fp_add(fp_dbl(A),A);let F=fp_sqr(E);
    let X3=fp_sub(F,fp_dbl(D));
    let Y3=fp_sub(fp_mul(E,fp_sub(D,X3)),fp_dbl(fp_dbl(fp_dbl(C))));
    let Z3=fp_mul(fp_dbl(Y1),Z1);return JacPt(X3,Y3,Z3);}
fn jac_add(p:JacPt,q:JacPt)->JacPt{
    if(jac_is_inf(p)){return q;}if(jac_is_inf(q)){return p;}
    let X1=p.x;let Y1=p.y;let Z1=p.z;let X2=q.x;let Y2=q.y;let Z2=q.z;
    let Z1Z1=fp_sqr(Z1);let Z2Z2=fp_sqr(Z2);
    let U1=fp_mul(X1,Z2Z2);let U2=fp_mul(X2,Z1Z1);
    let S1=fp_mul(fp_mul(Y1,Z2),Z2Z2);let S2=fp_mul(fp_mul(Y2,Z1),Z1Z1);
    let H=fp_sub(U2,U1);let I=fp_sqr(fp_dbl(H));let J=fp_mul(H,I);
    let r_=fp_dbl(fp_sub(S2,S1));let V=fp_mul(U1,I);
    let X3=fp_sub(fp_sub(fp_sqr(r_),J),fp_dbl(V));
    let Y3=fp_sub(fp_mul(r_,fp_sub(V,X3)),fp_dbl(fp_mul(S1,J)));
    let Z3=fp_mul(fp_sub(fp_sub(fp_sqr(fp_add(Z1,Z2)),Z1Z1),Z2Z2),H);
    return JacPt(X3,Y3,Z3);}
fn jac_to_affine(p:JacPt)->array<U256,2>{
    var r:array<U256,2>;
    let zi=fp_inv(p.z);let zi2=fp_sqr(zi);let zi3=fp_mul(zi2,zi);
    r[0]=from_mont(fp_mul(p.x,zi2));r[1]=from_mont(fp_mul(p.y,zi3));return r;}
fn scalar_mult_G(k:U256)->JacPt{
    var G:JacPt;
    G.x=u256w(GXM0,GXM1,GXM2,GXM3,GXM4,GXM5,GXM6,GXM7);
    G.y=u256w(GYM0,GYM1,GYM2,GYM3,GYM4,GYM5,GYM6,GYM7);
    G.z=fp_mont1();var R=jac_inf();var i:i32=255;
    loop{if(i<0){break;}
        let wi=u32(i)/32u;let bi=u32(i)%32u;
        let bit=(gw(k,7u-wi)>>bi)&1u;
        R=jac_dbl(R);if(bit==1u){R=jac_add(R,G);}i-=1;}
    return R;}
fn rotr(x:u32,n:u32)->u32{return(x>>n)|(x<<(32u-n));}
struct Hash256{hi:vec4<u32>,lo:vec4<u32>};
// SHA256 of 33-byte compressed pubkey (prefix||Qx), one block, fully unrolled
fn sha256_33(prefix:u32,x:U256)->Hash256{
    let x0=x.hi.x;let x1=x.hi.y;let x2=x.hi.z;let x3=x.hi.w;
    let x4=x.lo.x;let x5=x.lo.y;let x6=x.lo.z;let x7=x.lo.w;
    // Pad 33 bytes into 64-byte block
    let w00=(prefix<<24u)|(x0>>8u);
    let w01=(x0<<24u)|(x1>>8u);
    let w02=(x1<<24u)|(x2>>8u);
    let w03=(x2<<24u)|(x3>>8u);
    let w04=(x3<<24u)|(x4>>8u);
    let w05=(x4<<24u)|(x5>>8u);
    let w06=(x5<<24u)|(x6>>8u);
    let w07=(x6<<24u)|(x7>>8u);
    let w08=(x7<<24u)|0x800000u;
    let w09=0u;let w10=0u;let w11=0u;let w12=0u;let w13=0u;
    let w14=0u;let w15=264u;
    // Message schedule w16..w63
    let w16=w00+(rotr(w01,7u)^rotr(w01,18u)^(w01>>3u))+w09+(rotr(w14,17u)^rotr(w14,19u)^(w14>>10u));
    let w17=w01+(rotr(w02,7u)^rotr(w02,18u)^(w02>>3u))+w10+(rotr(w15,17u)^rotr(w15,19u)^(w15>>10u));
    let w18=w02+(rotr(w03,7u)^rotr(w03,18u)^(w03>>3u))+w11+(rotr(w16,17u)^rotr(w16,19u)^(w16>>10u));
    let w19=w03+(rotr(w04,7u)^rotr(w04,18u)^(w04>>3u))+w12+(rotr(w17,17u)^rotr(w17,19u)^(w17>>10u));
    let w20=w04+(rotr(w05,7u)^rotr(w05,18u)^(w05>>3u))+w13+(rotr(w18,17u)^rotr(w18,19u)^(w18>>10u));
    let w21=w05+(rotr(w06,7u)^rotr(w06,18u)^(w06>>3u))+w14+(rotr(w19,17u)^rotr(w19,19u)^(w19>>10u));
    let w22=w06+(rotr(w07,7u)^rotr(w07,18u)^(w07>>3u))+w15+(rotr(w20,17u)^rotr(w20,19u)^(w20>>10u));
    let w23=w07+(rotr(w08,7u)^rotr(w08,18u)^(w08>>3u))+w16+(rotr(w21,17u)^rotr(w21,19u)^(w21>>10u));
    let w24=w08+(rotr(w09,7u)^rotr(w09,18u)^(w09>>3u))+w17+(rotr(w22,17u)^rotr(w22,19u)^(w22>>10u));
    let w25=w09+(rotr(w10,7u)^rotr(w10,18u)^(w10>>3u))+w18+(rotr(w23,17u)^rotr(w23,19u)^(w23>>10u));
    let w26=w10+(rotr(w11,7u)^rotr(w11,18u)^(w11>>3u))+w19+(rotr(w24,17u)^rotr(w24,19u)^(w24>>10u));
    let w27=w11+(rotr(w12,7u)^rotr(w12,18u)^(w12>>3u))+w20+(rotr(w25,17u)^rotr(w25,19u)^(w25>>10u));
    let w28=w12+(rotr(w13,7u)^rotr(w13,18u)^(w13>>3u))+w21+(rotr(w26,17u)^rotr(w26,19u)^(w26>>10u));
    let w29=w13+(rotr(w14,7u)^rotr(w14,18u)^(w14>>3u))+w22+(rotr(w27,17u)^rotr(w27,19u)^(w27>>10u));
    let w30=w14+(rotr(w15,7u)^rotr(w15,18u)^(w15>>3u))+w23+(rotr(w28,17u)^rotr(w28,19u)^(w28>>10u));
    let w31=w15+(rotr(w16,7u)^rotr(w16,18u)^(w16>>3u))+w24+(rotr(w29,17u)^rotr(w29,19u)^(w29>>10u));
    let w32=w16+(rotr(w17,7u)^rotr(w17,18u)^(w17>>3u))+w25+(rotr(w30,17u)^rotr(w30,19u)^(w30>>10u));
    let w33=w17+(rotr(w18,7u)^rotr(w18,18u)^(w18>>3u))+w26+(rotr(w31,17u)^rotr(w31,19u)^(w31>>10u));
    let w34=w18+(rotr(w19,7u)^rotr(w19,18u)^(w19>>3u))+w27+(rotr(w32,17u)^rotr(w32,19u)^(w32>>10u));
    let w35=w19+(rotr(w20,7u)^rotr(w20,18u)^(w20>>3u))+w28+(rotr(w33,17u)^rotr(w33,19u)^(w33>>10u));
    let w36=w20+(rotr(w21,7u)^rotr(w21,18u)^(w21>>3u))+w29+(rotr(w34,17u)^rotr(w34,19u)^(w34>>10u));
    let w37=w21+(rotr(w22,7u)^rotr(w22,18u)^(w22>>3u))+w30+(rotr(w35,17u)^rotr(w35,19u)^(w35>>10u));
    let w38=w22+(rotr(w23,7u)^rotr(w23,18u)^(w23>>3u))+w31+(rotr(w36,17u)^rotr(w36,19u)^(w36>>10u));
    let w39=w23+(rotr(w24,7u)^rotr(w24,18u)^(w24>>3u))+w32+(rotr(w37,17u)^rotr(w37,19u)^(w37>>10u));
    let w40=w24+(rotr(w25,7u)^rotr(w25,18u)^(w25>>3u))+w33+(rotr(w38,17u)^rotr(w38,19u)^(w38>>10u));
    let w41=w25+(rotr(w26,7u)^rotr(w26,18u)^(w26>>3u))+w34+(rotr(w39,17u)^rotr(w39,19u)^(w39>>10u));
    let w42=w26+(rotr(w27,7u)^rotr(w27,18u)^(w27>>3u))+w35+(rotr(w40,17u)^rotr(w40,19u)^(w40>>10u));
    let w43=w27+(rotr(w28,7u)^rotr(w28,18u)^(w28>>3u))+w36+(rotr(w41,17u)^rotr(w41,19u)^(w41>>10u));
    let w44=w28+(rotr(w29,7u)^rotr(w29,18u)^(w29>>3u))+w37+(rotr(w42,17u)^rotr(w42,19u)^(w42>>10u));
    let w45=w29+(rotr(w30,7u)^rotr(w30,18u)^(w30>>3u))+w38+(rotr(w43,17u)^rotr(w43,19u)^(w43>>10u));
    let w46=w30+(rotr(w31,7u)^rotr(w31,18u)^(w31>>3u))+w39+(rotr(w44,17u)^rotr(w44,19u)^(w44>>10u));
    let w47=w31+(rotr(w32,7u)^rotr(w32,18u)^(w32>>3u))+w40+(rotr(w45,17u)^rotr(w45,19u)^(w45>>10u));
    let w48=w32+(rotr(w33,7u)^rotr(w33,18u)^(w33>>3u))+w41+(rotr(w46,17u)^rotr(w46,19u)^(w46>>10u));
    let w49=w33+(rotr(w34,7u)^rotr(w34,18u)^(w34>>3u))+w42+(rotr(w47,17u)^rotr(w47,19u)^(w47>>10u));
    let w50=w34+(rotr(w35,7u)^rotr(w35,18u)^(w35>>3u))+w43+(rotr(w48,17u)^rotr(w48,19u)^(w48>>10u));
    let w51=w35+(rotr(w36,7u)^rotr(w36,18u)^(w36>>3u))+w44+(rotr(w49,17u)^rotr(w49,19u)^(w49>>10u));
    let w52=w36+(rotr(w37,7u)^rotr(w37,18u)^(w37>>3u))+w45+(rotr(w50,17u)^rotr(w50,19u)^(w50>>10u));
    let w53=w37+(rotr(w38,7u)^rotr(w38,18u)^(w38>>3u))+w46+(rotr(w51,17u)^rotr(w51,19u)^(w51>>10u));
    let w54=w38+(rotr(w39,7u)^rotr(w39,18u)^(w39>>3u))+w47+(rotr(w52,17u)^rotr(w52,19u)^(w52>>10u));
    let w55=w39+(rotr(w40,7u)^rotr(w40,18u)^(w40>>3u))+w48+(rotr(w53,17u)^rotr(w53,19u)^(w53>>10u));
    let w56=w40+(rotr(w41,7u)^rotr(w41,18u)^(w41>>3u))+w49+(rotr(w54,17u)^rotr(w54,19u)^(w54>>10u));
    let w57=w41+(rotr(w42,7u)^rotr(w42,18u)^(w42>>3u))+w50+(rotr(w55,17u)^rotr(w55,19u)^(w55>>10u));
    let w58=w42+(rotr(w43,7u)^rotr(w43,18u)^(w43>>3u))+w51+(rotr(w56,17u)^rotr(w56,19u)^(w56>>10u));
    let w59=w43+(rotr(w44,7u)^rotr(w44,18u)^(w44>>3u))+w52+(rotr(w57,17u)^rotr(w57,19u)^(w57>>10u));
    let w60=w44+(rotr(w45,7u)^rotr(w45,18u)^(w45>>3u))+w53+(rotr(w58,17u)^rotr(w58,19u)^(w58>>10u));
    let w61=w45+(rotr(w46,7u)^rotr(w46,18u)^(w46>>3u))+w54+(rotr(w59,17u)^rotr(w59,19u)^(w59>>10u));
    let w62=w46+(rotr(w47,7u)^rotr(w47,18u)^(w47>>3u))+w55+(rotr(w60,17u)^rotr(w60,19u)^(w60>>10u));
    let w63=w47+(rotr(w48,7u)^rotr(w48,18u)^(w48>>3u))+w56+(rotr(w61,17u)^rotr(w61,19u)^(w61>>10u));
    // Initial hash values
    var ra=0x6a09e667u;var rb=0xbb67ae85u;var rc=0x3c6ef372u;var rd=0xa54ff53au;
    var re=0x510e527fu;var rf=0x9b05688cu;var rg=0x1f83d9abu;var rh=0x5be0cd19u;
    // 64 rounds
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x428a2f98u+w00;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x71374491u+w01;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xb5c0fbcfu+w02;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xe9b5dba5u+w03;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x3956c25bu+w04;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x59f111f1u+w05;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x923f82a4u+w06;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xab1c5ed5u+w07;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xd807aa98u+w08;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x12835b01u+w09;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x243185beu+w10;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x550c7dc3u+w11;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x72be5d74u+w12;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x80deb1feu+w13;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x9bdc06a7u+w14;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xc19bf174u+w15;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xe49b69c1u+w16;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xefbe4786u+w17;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x0fc19dc6u+w18;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x240ca1ccu+w19;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x2de92c6fu+w20;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x4a7484aau+w21;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x5cb0a9dcu+w22;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x76f988dau+w23;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x983e5152u+w24;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xa831c66du+w25;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xb00327c8u+w26;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xbf597fc7u+w27;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xc6e00bf3u+w28;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xd5a79147u+w29;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x06ca6351u+w30;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x14292967u+w31;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x27b70a85u+w32;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x2e1b2138u+w33;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x4d2c6dfcu+w34;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x53380d13u+w35;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x650a7354u+w36;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x766a0abbu+w37;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x81c2c92eu+w38;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x92722c85u+w39;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xa2bfe8a1u+w40;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xa81a664bu+w41;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xc24b8b70u+w42;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xc76c51a3u+w43;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xd192e819u+w44;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xd6990624u+w45;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xf40e3585u+w46;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x106aa070u+w47;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x19a4c116u+w48;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x1e376c08u+w49;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x2748774cu+w50;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x34b0bcb5u+w51;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x391c0cb3u+w52;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x4ed8aa4au+w53;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x5b9cca4fu+w54;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x682e6ff3u+w55;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x748f82eeu+w56;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x78a5636fu+w57;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x84c87814u+w58;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x8cc70208u+w59;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0x90befffau+w60;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xa4506cebu+w61;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xbef9a3f7u+w62;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    {let S1_=rotr(re,6u)^rotr(re,11u)^rotr(re,25u);
     let ch_=(re&rf)^(~re&rg);
     let T1_=rh+S1_+ch_+0xc67178f2u+w63;
     let S0_=rotr(ra,2u)^rotr(ra,13u)^rotr(ra,22u);
     let mj_=(ra&rb)^(ra&rc)^(rb&rc);
     let T2_=S0_+mj_;
     let new_a_=T1_+T2_;
     rh=rg;rg=rf;rf=re;re=rd+T1_;rd=rc;rc=rb;rb=ra;ra=new_a_;}
    return Hash256(
        vec4<u32>(0x6a09e667u+ra,0xbb67ae85u+rb,0x3c6ef372u+rc,0xa54ff53au+rd),
        vec4<u32>(0x510e527fu+re,0x9b05688cu+rf,0x1f83d9abu+rg,0x5be0cd19u+rh),
    );
}
fn bswap(v:u32)->u32{return((v&0xFFu)<<24u)|(((v>>8u)&0xFFu)<<16u)|(((v>>16u)&0xFFu)<<8u)|(v>>24u);}
fn rmd_f(x:u32,y:u32,z:u32,j:u32)->u32{
    if(j<16u){return x^y^z;}if(j<32u){return(x&y)|(~x&z);}
    if(j<48u){return(x|~y)^z;}if(j<64u){return(x&z)|(y&~z);}return x^(y|~z);}
fn rmd_KL(j:u32)->u32{
    if(j<16u){return 0u;}if(j<32u){return 0x5A827999u;}
    if(j<48u){return 0x6ED9EBA1u;}if(j<64u){return 0x8F1BBCDCu;}return 0xA953FD4Eu;}
fn rmd_KR(j:u32)->u32{
    if(j<16u){return 0x50A28BE6u;}if(j<32u){return 0x5C4DD124u;}
    if(j<48u){return 0x6D703EF3u;}if(j<64u){return 0x7A6D76E9u;}return 0u;}
fn rmd_RL(j:u32)->u32{
    switch(j){
        case 0u:{return 0u;}case 1u:{return 1u;}case 2u:{return 2u;}case 3u:{return 3u;}
        case 4u:{return 4u;}case 5u:{return 5u;}case 6u:{return 6u;}case 7u:{return 7u;}
        case 8u:{return 8u;}case 9u:{return 9u;}case 10u:{return 10u;}case 11u:{return 11u;}
        case 12u:{return 12u;}case 13u:{return 13u;}case 14u:{return 14u;}case 15u:{return 15u;}
        case 16u:{return 7u;}case 17u:{return 4u;}case 18u:{return 13u;}case 19u:{return 1u;}
        case 20u:{return 10u;}case 21u:{return 6u;}case 22u:{return 15u;}case 23u:{return 3u;}
        case 24u:{return 12u;}case 25u:{return 0u;}case 26u:{return 9u;}case 27u:{return 5u;}
        case 28u:{return 2u;}case 29u:{return 14u;}case 30u:{return 11u;}case 31u:{return 8u;}
        case 32u:{return 3u;}case 33u:{return 10u;}case 34u:{return 14u;}case 35u:{return 4u;}
        case 36u:{return 9u;}case 37u:{return 15u;}case 38u:{return 8u;}case 39u:{return 1u;}
        case 40u:{return 2u;}case 41u:{return 7u;}case 42u:{return 0u;}case 43u:{return 6u;}
        case 44u:{return 13u;}case 45u:{return 11u;}case 46u:{return 5u;}case 47u:{return 12u;}
        case 48u:{return 1u;}case 49u:{return 9u;}case 50u:{return 11u;}case 51u:{return 10u;}
        case 52u:{return 0u;}case 53u:{return 8u;}case 54u:{return 12u;}case 55u:{return 4u;}
        case 56u:{return 13u;}case 57u:{return 3u;}case 58u:{return 7u;}case 59u:{return 15u;}
        case 60u:{return 14u;}case 61u:{return 5u;}case 62u:{return 6u;}case 63u:{return 2u;}
        case 64u:{return 4u;}case 65u:{return 0u;}case 66u:{return 5u;}case 67u:{return 9u;}
        case 68u:{return 7u;}case 69u:{return 12u;}case 70u:{return 2u;}case 71u:{return 10u;}
        case 72u:{return 14u;}case 73u:{return 1u;}case 74u:{return 3u;}case 75u:{return 8u;}
        case 76u:{return 11u;}case 77u:{return 6u;}case 78u:{return 15u;}default:{return 13u;}}}
fn rmd_RR(j:u32)->u32{
    switch(j){
        case 0u:{return 5u;}case 1u:{return 14u;}case 2u:{return 7u;}case 3u:{return 0u;}
        case 4u:{return 9u;}case 5u:{return 2u;}case 6u:{return 11u;}case 7u:{return 4u;}
        case 8u:{return 13u;}case 9u:{return 6u;}case 10u:{return 15u;}case 11u:{return 8u;}
        case 12u:{return 1u;}case 13u:{return 10u;}case 14u:{return 3u;}case 15u:{return 12u;}
        case 16u:{return 6u;}case 17u:{return 11u;}case 18u:{return 3u;}case 19u:{return 7u;}
        case 20u:{return 0u;}case 21u:{return 13u;}case 22u:{return 5u;}case 23u:{return 10u;}
        case 24u:{return 14u;}case 25u:{return 15u;}case 26u:{return 8u;}case 27u:{return 12u;}
        case 28u:{return 4u;}case 29u:{return 9u;}case 30u:{return 1u;}case 31u:{return 2u;}
        case 32u:{return 15u;}case 33u:{return 5u;}case 34u:{return 1u;}case 35u:{return 3u;}
        case 36u:{return 7u;}case 37u:{return 14u;}case 38u:{return 6u;}case 39u:{return 9u;}
        case 40u:{return 11u;}case 41u:{return 8u;}case 42u:{return 12u;}case 43u:{return 2u;}
        case 44u:{return 10u;}case 45u:{return 0u;}case 46u:{return 4u;}case 47u:{return 13u;}
        case 48u:{return 8u;}case 49u:{return 6u;}case 50u:{return 4u;}case 51u:{return 1u;}
        case 52u:{return 3u;}case 53u:{return 11u;}case 54u:{return 15u;}case 55u:{return 0u;}
        case 56u:{return 5u;}case 57u:{return 12u;}case 58u:{return 2u;}case 59u:{return 13u;}
        case 60u:{return 9u;}case 61u:{return 7u;}case 62u:{return 10u;}case 63u:{return 14u;}
        case 64u:{return 12u;}case 65u:{return 15u;}case 66u:{return 10u;}case 67u:{return 4u;}
        case 68u:{return 1u;}case 69u:{return 5u;}case 70u:{return 8u;}case 71u:{return 7u;}
        case 72u:{return 6u;}case 73u:{return 2u;}case 74u:{return 13u;}case 75u:{return 14u;}
        case 76u:{return 0u;}case 77u:{return 3u;}case 78u:{return 9u;}default:{return 11u;}}}
fn rmd_SL(j:u32)->u32{
    switch(j){
        case 0u:{return 11u;}case 1u:{return 14u;}case 2u:{return 15u;}case 3u:{return 12u;}
        case 4u:{return 5u;}case 5u:{return 8u;}case 6u:{return 7u;}case 7u:{return 9u;}
        case 8u:{return 11u;}case 9u:{return 13u;}case 10u:{return 14u;}case 11u:{return 15u;}
        case 12u:{return 6u;}case 13u:{return 7u;}case 14u:{return 9u;}case 15u:{return 8u;}
        case 16u:{return 7u;}case 17u:{return 6u;}case 18u:{return 8u;}case 19u:{return 13u;}
        case 20u:{return 11u;}case 21u:{return 9u;}case 22u:{return 7u;}case 23u:{return 15u;}
        case 24u:{return 7u;}case 25u:{return 12u;}case 26u:{return 15u;}case 27u:{return 9u;}
        case 28u:{return 11u;}case 29u:{return 7u;}case 30u:{return 13u;}case 31u:{return 12u;}
        case 32u:{return 11u;}case 33u:{return 13u;}case 34u:{return 6u;}case 35u:{return 7u;}
        case 36u:{return 14u;}case 37u:{return 9u;}case 38u:{return 13u;}case 39u:{return 15u;}
        case 40u:{return 14u;}case 41u:{return 8u;}case 42u:{return 13u;}case 43u:{return 6u;}
        case 44u:{return 5u;}case 45u:{return 12u;}case 46u:{return 7u;}case 47u:{return 5u;}
        case 48u:{return 11u;}case 49u:{return 12u;}case 50u:{return 14u;}case 51u:{return 15u;}
        case 52u:{return 14u;}case 53u:{return 15u;}case 54u:{return 9u;}case 55u:{return 8u;}
        case 56u:{return 9u;}case 57u:{return 14u;}case 58u:{return 5u;}case 59u:{return 6u;}
        case 60u:{return 8u;}case 61u:{return 6u;}case 62u:{return 5u;}case 63u:{return 12u;}
        case 64u:{return 9u;}case 65u:{return 15u;}case 66u:{return 5u;}case 67u:{return 11u;}
        case 68u:{return 6u;}case 69u:{return 8u;}case 70u:{return 13u;}case 71u:{return 12u;}
        case 72u:{return 5u;}case 73u:{return 12u;}case 74u:{return 13u;}case 75u:{return 14u;}
        case 76u:{return 11u;}case 77u:{return 8u;}case 78u:{return 5u;}default:{return 6u;}}}
fn rmd_SR(j:u32)->u32{
    switch(j){
        case 0u:{return 8u;}case 1u:{return 9u;}case 2u:{return 9u;}case 3u:{return 11u;}
        case 4u:{return 13u;}case 5u:{return 15u;}case 6u:{return 15u;}case 7u:{return 5u;}
        case 8u:{return 7u;}case 9u:{return 7u;}case 10u:{return 8u;}case 11u:{return 11u;}
        case 12u:{return 14u;}case 13u:{return 14u;}case 14u:{return 12u;}case 15u:{return 6u;}
        case 16u:{return 9u;}case 17u:{return 13u;}case 18u:{return 15u;}case 19u:{return 7u;}
        case 20u:{return 12u;}case 21u:{return 8u;}case 22u:{return 9u;}case 23u:{return 11u;}
        case 24u:{return 7u;}case 25u:{return 7u;}case 26u:{return 12u;}case 27u:{return 7u;}
        case 28u:{return 6u;}case 29u:{return 15u;}case 30u:{return 13u;}case 31u:{return 11u;}
        case 32u:{return 9u;}case 33u:{return 7u;}case 34u:{return 15u;}case 35u:{return 11u;}
        case 36u:{return 8u;}case 37u:{return 6u;}case 38u:{return 6u;}case 39u:{return 14u;}
        case 40u:{return 12u;}case 41u:{return 13u;}case 42u:{return 5u;}case 43u:{return 14u;}
        case 44u:{return 13u;}case 45u:{return 13u;}case 46u:{return 7u;}case 47u:{return 5u;}
        case 48u:{return 15u;}case 49u:{return 5u;}case 50u:{return 8u;}case 51u:{return 11u;}
        case 52u:{return 14u;}case 53u:{return 14u;}case 54u:{return 6u;}case 55u:{return 14u;}
        case 56u:{return 6u;}case 57u:{return 9u;}case 58u:{return 12u;}case 59u:{return 9u;}
        case 60u:{return 12u;}case 61u:{return 5u;}case 62u:{return 15u;}case 63u:{return 8u;}
        case 64u:{return 8u;}case 65u:{return 5u;}case 66u:{return 12u;}case 67u:{return 9u;}
        case 68u:{return 12u;}case 69u:{return 5u;}case 70u:{return 14u;}case 71u:{return 6u;}
        case 72u:{return 8u;}case 73u:{return 13u;}case 74u:{return 6u;}case 75u:{return 5u;}
        case 76u:{return 15u;}case 77u:{return 13u;}case 78u:{return 11u;}default:{return 11u;}}}
fn rmd_X(x0:u32,x1:u32,x2:u32,x3:u32,x4:u32,x5:u32,x6:u32,x7:u32,
         x8:u32,x9:u32,x10:u32,x11:u32,x12:u32,x13:u32,x14:u32,x15:u32,i:u32)->u32{
    switch(i){
        case 0u:{return x0;}case 1u:{return x1;}case 2u:{return x2;}case 3u:{return x3;}
        case 4u:{return x4;}case 5u:{return x5;}case 6u:{return x6;}case 7u:{return x7;}
        case 8u:{return x8;}case 9u:{return x9;}case 10u:{return x10;}case 11u:{return x11;}
        case 12u:{return x12;}case 13u:{return x13;}case 14u:{return x14;}default:{return x15;}}}
struct Hash160{w0:u32,w1:u32,w2:u32,w3:u32,w4:u32};
fn ripemd160(sha:Hash256)->Hash160{
    let x0=bswap(sha.hi.x);let x1=bswap(sha.hi.y);let x2=bswap(sha.hi.z);let x3=bswap(sha.hi.w);
    let x4=bswap(sha.lo.x);let x5=bswap(sha.lo.y);let x6=bswap(sha.lo.z);let x7=bswap(sha.lo.w);
    let x8=0x00000080u;let x9=0u;let x10=0u;let x11=0u;
    let x12=0u;let x13=0u;let x14=256u;let x15=0u;
    var h0=0x67452301u;var h1=0xEFCDAB89u;var h2=0x98BADCFEu;
    var h3=0x10325476u;var h4=0xC3D2E1F0u;
    var al=h0;var bl=h1;var cl=h2;var dl=h3;var el=h4;
    var ar=h0;var br=h1;var cr=h2;var dr=h3;var er=h4;
    for(var j=0u;j<80u;j++){
        let xi_l=rmd_X(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,rmd_RL(j));
        let T=rotl(al+rmd_f(bl,cl,dl,j)+xi_l+rmd_KL(j),rmd_SL(j))+el;
        al=el;el=dl;dl=rotl(cl,10u);cl=bl;bl=T;
        let xi_r=rmd_X(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,rmd_RR(j));
        let U=rotl(ar+rmd_f(br,cr,dr,79u-j)+xi_r+rmd_KR(j),rmd_SR(j))+er;
        ar=er;er=dr;dr=rotl(cr,10u);cr=br;br=U;}
    let tt=h1+cl+dr;h1=h2+dl+er;h2=h3+el+ar;h3=h4+al+br;h4=h0+bl+cr;h0=tt;
    return Hash160(bswap(h0),bswap(h1),bswap(h2),bswap(h3),bswap(h4));}
fn rotl(x:u32,n:u32)->u32{return(x<<n)|(x>>(32u-n));}
fn bloom_check(h:Hash160)->bool{
    let n=arrayLength(&bloom_filter)*32u;
    var fh:u32=2166136261u;
    fh=(fh^((h.w0>>24u)&0xFFu))*16777619u;fh=(fh^((h.w0>>16u)&0xFFu))*16777619u;
    fh=(fh^((h.w0>> 8u)&0xFFu))*16777619u;fh=(fh^(h.w0&0xFFu))*16777619u;
    fh=(fh^((h.w1>>24u)&0xFFu))*16777619u;fh=(fh^((h.w1>>16u)&0xFFu))*16777619u;
    fh=(fh^((h.w1>> 8u)&0xFFu))*16777619u;fh=(fh^(h.w1&0xFFu))*16777619u;
    fh=(fh^((h.w2>>24u)&0xFFu))*16777619u;fh=(fh^((h.w2>>16u)&0xFFu))*16777619u;
    fh=(fh^((h.w2>> 8u)&0xFFu))*16777619u;fh=(fh^(h.w2&0xFFu))*16777619u;
    fh=(fh^((h.w3>>24u)&0xFFu))*16777619u;fh=(fh^((h.w3>>16u)&0xFFu))*16777619u;
    fh=(fh^((h.w3>> 8u)&0xFFu))*16777619u;fh=(fh^(h.w3&0xFFu))*16777619u;
    fh=(fh^((h.w4>>24u)&0xFFu))*16777619u;fh=(fh^((h.w4>>16u)&0xFFu))*16777619u;
    fh=(fh^((h.w4>> 8u)&0xFFu))*16777619u;fh=(fh^(h.w4&0xFFu))*16777619u;
    var fh2=fh^(fh>>16u);fh2*=0x45d9f3bu;fh2^=fh2>>16u;
    for(var k=0u;k<15u;k++){
        let idx=(fh+k*fh2)%n;
        if(((bloom_filter[idx/32u]>>(idx%32u))&1u)==0u){return false;}}
    return true;}
fn arc4_init(slot:u32,seed_lo:u32,seed_hi:u32){
    let b=slot*256u;
    for(var n=0u;n<256u;n++){arc4_state[b+n]=n;}
    var j=0u;
    for(var n=0u;n<256u;n++){
        let ki=n&7u;var kb:u32;
        if(ki<4u){kb=(seed_lo>>(ki*8u))&0xFFu;}else{kb=(seed_hi>>((ki-4u)*8u))&0xFFu;}
        j=(j+arc4_state[b+n]+kb)&0xFFu;
        let tmp=arc4_state[b+n];arc4_state[b+n]=arc4_state[b+j];arc4_state[b+j]=tmp;}}
fn arc4_byte(slot:u32,ij:ptr<function,u32>)->u32{
    let b=slot*256u;
    var ii=(*ij>>8u)&0xFFu;var jj=(*ij)&0xFFu;
    ii=(ii+1u)&0xFFu;jj=(jj+arc4_state[b+ii])&0xFFu;
    let tmp=arc4_state[b+ii];arc4_state[b+ii]=arc4_state[b+jj];arc4_state[b+jj]=tmp;
    *ij=(ii<<8u)|jj;
    return arc4_state[b+((arc4_state[b+ii]+arc4_state[b+jj])&0xFFu)];}
@compute @workgroup_size(64)
fn randstorm_main(@builtin(global_invocation_id) gid:vec3<u32>){
    let slot=gid.x;let base_fp=gid.x*TIMESTAMPS_PER_THREAD;
    let n_fps=arrayLength(&fingerprints);
    for(var t=0u;t<TIMESTAMPS_PER_THREAD;t++){
        let fp_idx=base_fp+t;if(fp_idx>=n_fps){return;}
        let fp=fingerprints[fp_idx];
        arc4_init(slot,fp.timestamp_lo,fp.timestamp_hi);
        var ij=0u;var k=u256z();
        for(var wi=0u;wi<8u;wi++){
            let b0=arc4_byte(slot,&ij);let b1=arc4_byte(slot,&ij);
            let b2=arc4_byte(slot,&ij);let b3=arc4_byte(slot,&ij);
            sw(&k,wi,(b0<<24u)|(b1<<16u)|(b2<<8u)|b3);}
        let out=fp_idx*RESULT_STRIDE;
        results[out+0u]=k.hi.x;results[out+1u]=k.hi.y;
        results[out+2u]=k.hi.z;results[out+3u]=k.hi.w;
        results[out+4u]=k.lo.x;results[out+5u]=k.lo.y;
        results[out+6u]=k.lo.z;results[out+7u]=k.lo.w;
        results[out+8u]=0u;results[out+9u]=0u;results[out+10u]=0u;
        results[out+11u]=0u;results[out+12u]=0u;results[out+13u]=0u;
        let Q=scalar_mult_G(k);if(jac_is_inf(Q)){continue;}
        let xy=jac_to_affine(Q);let Qx=xy[0];let Qy=xy[1];
        let prefix=2u+(gw(Qy,7u)&1u);
        let sha=sha256_33(prefix,Qx);
        let h160=ripemd160(sha);
        if(bloom_check(h160)){
            results[out+8u]=1u;
            results[out+9u]=h160.w0;results[out+10u]=h160.w1;
            results[out+11u]=h160.w2;results[out+12u]=h160.w3;
            results[out+13u]=h160.w4;}}}
