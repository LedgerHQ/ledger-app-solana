#include "token_info.h"
#include "util.h"

const TokenInfo TOKEN_REGISTRY[] = {
    // So11111111111111111111111111111111111111112
    {{{0x06, 0x9b, 0x88, 0x57, 0xfe, 0xab, 0x81, 0x84, 0xfb, 0x68, 0x7f,
       0x63, 0x46, 0x18, 0xc0, 0x35, 0xda, 0xc4, 0x39, 0xdc, 0x1a, 0xeb,
       0x3b, 0x55, 0x98, 0xa0, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x01}},
     "SOL"},

    // JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN
    {{{0x04, 0x79, 0xd9, 0xc7, 0xcc, 0x10, 0x35, 0xde, 0x72, 0x11, 0xf9,
       0x9e, 0xb4, 0x8c, 0x09, 0xd7, 0x0b, 0x2b, 0xdf, 0x5b, 0xdf, 0x9e,
       0x2e, 0x56, 0xb8, 0xa1, 0xfb, 0xb5, 0xa2, 0xea, 0x33, 0x27}},
     "JUP"},

    // HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3
    {{{0xf5, 0xed, 0xec, 0x84, 0x71, 0xc7, 0x56, 0x24, 0xeb, 0xc4, 0x07,
       0x9a, 0x63, 0x43, 0x26, 0xd9, 0x6a, 0x68, 0x9e, 0x61, 0x57, 0xd7,
       0x9a, 0xbe, 0x8f, 0x5a, 0x6f, 0x94, 0x47, 0x28, 0x53, 0xbc}},
     "PYTH"},

    // 85VBFQZC9TZkfaptBWjvUw7YbZjy52A6mjtPGjstQAmQ
    {{{0x69, 0x27, 0xfd, 0xc0, 0x1e, 0xa9, 0x06, 0xf9, 0x6d, 0x71, 0x37,
       0x87, 0x4c, 0xdd, 0x7a, 0xda, 0xd0, 0x0c, 0xa3, 0x57, 0x64, 0x61,
       0x93, 0x10, 0xe5, 0x41, 0x96, 0xc7, 0x81, 0xd8, 0x4d, 0x5b}},
     "W"},

    // jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL
    {{{0x0a, 0xfc, 0xf8, 0x96, 0x8b, 0x8d, 0xab, 0x88, 0x48, 0x1e, 0x2d,
       0x2a, 0xe6, 0x89, 0xc9, 0x52, 0xc7, 0x57, 0xae, 0xba, 0x64, 0x3e,
       0x39, 0x19, 0xe8, 0x9f, 0x2e, 0x55, 0x79, 0x5c, 0x76, 0xc1}},
     "JTO"},

    // EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
    {{{0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3,
       0x6a, 0xab, 0xc9, 0x74, 0x31, 0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6,
       0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61}},
     "USDC"},

    // Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB
    {{{0xce, 0x01, 0x0e, 0x60, 0xaf, 0xed, 0xb2, 0x27, 0x17, 0xbd, 0x63,
       0x19, 0x2f, 0x54, 0x14, 0x5a, 0x3f, 0x96, 0x5a, 0x33, 0xbb, 0x82,
       0xd2, 0xc7, 0x02, 0x9e, 0xb2, 0xce, 0x1e, 0x20, 0x82, 0x64}},
     "USDT"},

    // J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn
    {{{0xfc, 0xd1, 0x41, 0xe9, 0x83, 0x2c, 0xaf, 0x10, 0xad, 0x91, 0x74,
       0x95, 0xca, 0x0f, 0x27, 0x1b, 0x5b, 0x29, 0x3c, 0xd4, 0x70, 0x27,
       0xea, 0x73, 0x70, 0x07, 0xed, 0x40, 0xeb, 0x39, 0xa0, 0xbd}},
     "JITOSOL"},

    // NeonTjSjsuo3rexg9o6vHuMXw62f9V7zvmu8M8Zut44
    {{{0x05, 0x8b, 0xf1, 0xf0, 0x0d, 0x16, 0x7d, 0x3d, 0xf3, 0x14, 0x91,
       0xda, 0xe2, 0x04, 0xd6, 0x00, 0x6b, 0x9d, 0x59, 0x68, 0x70, 0xee,
       0xcf, 0x5d, 0x30, 0x50, 0x35, 0xdf, 0x8a, 0x3f, 0x96, 0xdd}},
     "NEON"},

    // TNSRxcUxoT9xBG3de7PiJyTDYu7kskLqcpddxnEJAS6
    {{{0x06, 0xc1, 0x57, 0x71, 0x54, 0x65, 0x74, 0x9f, 0x07, 0x0a, 0x30,
       0x0e, 0x6d, 0xf4, 0xb0, 0xd4, 0xc9, 0xf0, 0x86, 0xfd, 0xe4, 0x27,
       0xee, 0x20, 0x2e, 0x04, 0x71, 0x1f, 0xe6, 0x20, 0x87, 0x4b}},
     "TNSR"},

    // 4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R
    {{{0x37, 0x99, 0x8c, 0xcb, 0xf2, 0xd0, 0x45, 0x8b, 0x61, 0x5c, 0xbc,
       0xc6, 0xb1, 0xa3, 0x67, 0xc4, 0x74, 0x9e, 0x9f, 0xef, 0x73, 0x06,
       0x62, 0x2e, 0x1b, 0x1b, 0x58, 0x91, 0x01, 0x20, 0xbc, 0x9a}},
     "RAY"},

    // mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So
    {{{0x0b, 0x62, 0xba, 0x07, 0x4f, 0x72, 0x2c, 0x9d, 0x41, 0x14, 0xf2,
       0xd8, 0xf7, 0x0a, 0x00, 0xc6, 0x60, 0x02, 0x33, 0x7b, 0x9b, 0xf9,
       0x0c, 0x87, 0x36, 0x57, 0xa6, 0xd2, 0x01, 0xdb, 0x4c, 0x80}},
     "mSOL"},

    // hntyVP6YFm1Hg25TN9WGLqM12b8TQmcknKrdu1oxWux
    {{{0x0a, 0x73, 0x20, 0x93, 0x91, 0x85, 0x61, 0xf7, 0xdd, 0x7f, 0xcb,
       0xec, 0x4a, 0xbd, 0x85, 0x13, 0xde, 0xca, 0x1a, 0x96, 0x7f, 0x7a,
       0xd7, 0xa3, 0x9d, 0x63, 0xb4, 0x1e, 0xd8, 0x93, 0x80, 0x8b}},
     "HNT"},

    // ZEUS1aR7aX8DFFJf5QjWj2ftDDdNTroMNGo8YoQm3Gq
    {{{0x08, 0x41, 0xd1, 0xde, 0xc7, 0x88, 0xd0, 0x8c, 0xc0, 0xe4, 0x48,
       0xd2, 0xd6, 0xdf, 0x7a, 0xf6, 0x94, 0xcd, 0x1c, 0x5a, 0x4d, 0x56,
       0x76, 0xce, 0x91, 0x47, 0x55, 0x91, 0xe1, 0x88, 0xbf, 0x2e}},
     "ZEUS"},

    // 4vMsoUT2BWatFweudnQM1xedRLfJgJ7hswhcpz4xgBTy
    {{{0x3a, 0x3e, 0x72, 0xb6, 0x7e, 0xa9, 0x4e, 0x17, 0x65, 0x00, 0x4e,
       0xf6, 0x82, 0x44, 0xf6, 0xb0, 0xb3, 0x2d, 0xdd, 0xe7, 0x43, 0xa3,
       0x3b, 0x20, 0xf9, 0x14, 0x30, 0xe1, 0xe8, 0x17, 0xc1, 0xac}},
     "HONEY"},

    // 7i5KKsX2weiTkry7jA4ZwSuXGhs5eJBEjY8vVxR4pfRx
    {{{0x63, 0xab, 0xd0, 0x96, 0x70, 0x76, 0xf5, 0x8b, 0xa2, 0xed, 0xad,
       0xb4, 0x1f, 0x10, 0x71, 0x9d, 0xf1, 0x35, 0x4a, 0xbe, 0x11, 0x8f,
       0x29, 0xa8, 0xf3, 0x0e, 0xe6, 0x63, 0x94, 0x74, 0xb9, 0x47}},
     "GMT"},

    // 4LLbsb5ReP3yEtYzmXewyGjcir5uXtKFURtaEUVC2AHs
    {{{0x31, 0x87, 0x42, 0x64, 0xbc, 0xf1, 0x4d, 0xc1, 0x0c, 0x59, 0x90,
       0x38, 0x92, 0x8c, 0x3c, 0x17, 0x9f, 0xac, 0x41, 0xfd, 0x25, 0x2b,
       0x15, 0x5b, 0x40, 0xfb, 0x88, 0x8a, 0xd2, 0xf8, 0xf9, 0xae}},
     "PRCL"},

    // nosXBVoaCTtYdLvKY6Csb4AC8JCdQKKAaWYtx2ZMoo7
    {{{0x0b, 0xbc, 0x22, 0x37, 0xbe, 0x47, 0x53, 0x50, 0xaf, 0xd9, 0x8b,
       0xec, 0x57, 0x96, 0x8d, 0xa2, 0xd8, 0xae, 0x7f, 0x47, 0x73, 0xf9,
       0x7f, 0x67, 0x4c, 0x94, 0xa7, 0x2e, 0x02, 0xa5, 0xf5, 0xea}},
     "NOS"},

    // bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1
    {{{0x08, 0xd2, 0xe9, 0x70, 0xf9, 0x3c, 0x7b, 0x3d, 0x50, 0x19, 0x1e,
       0x61, 0x1a, 0xcd, 0x93, 0xaa, 0x80, 0xa5, 0x46, 0xb4, 0x5e, 0xc9,
       0x65, 0xe1, 0x8b, 0x05, 0x87, 0x15, 0x56, 0x99, 0xc8, 0xac}},
     "bSOL"},

    // RLBxxFkseAZ4RgJH3Sqn8jXxhmGoz9jWxDNJMh8pL7a
    {{{0x06, 0x3b, 0xa2, 0xf4, 0x69, 0x72, 0x05, 0xf5, 0x31, 0xb6, 0xde,
       0x49, 0xbb, 0x96, 0x05, 0xfd, 0x2c, 0xa6, 0xa9, 0xdd, 0xf2, 0x43,
       0xbe, 0xd2, 0x51, 0xfd, 0xa6, 0x55, 0x2e, 0xf0, 0xe5, 0x71}},
     "RLB"},

    // EchesyfXePKdLtoiZSL8pBe8Myagyy8ZRqsACNCFGnvp
    {{{0xca, 0x4d, 0x39, 0x96, 0x4c, 0x9c, 0xb5, 0xf9, 0x79, 0x0d, 0x0a,
       0x12, 0x96, 0x9f, 0x60, 0xfd, 0x97, 0x24, 0x93, 0x62, 0x84, 0xea,
       0x4a, 0x12, 0xda, 0xde, 0xd4, 0x2d, 0xdf, 0xa6, 0x9c, 0x5d}},
     "FIDA"},

    // rndrizKT3MK1iimdxRdWabcF7Zg7AR5T4nud4EkHBof
    {{{0x0c, 0xc1, 0x0f, 0x51, 0x6a, 0xaa, 0xe9, 0xc1, 0x4b, 0xa9, 0x47,
       0x1f, 0x60, 0xab, 0xd3, 0x92, 0xdc, 0xd7, 0x86, 0xd5, 0x73, 0x54,
       0xab, 0xed, 0xee, 0xe7, 0x28, 0x9d, 0xd4, 0x0a, 0x0a, 0x0a}},
     "RENDER"},

    // 27G8MtK7VtTcCHkpASjSDdkWWYfoqT6ggEuKidVJidD4
    {{{0x10, 0x76, 0x46, 0x9c, 0x10, 0x41, 0xd9, 0xe9, 0xb3, 0x9f, 0xc2,
       0xed, 0xe1, 0x13, 0x33, 0x97, 0x3b, 0x3e, 0x95, 0x73, 0x2a, 0x44,
       0x39, 0x20, 0x71, 0x93, 0xa6, 0x1c, 0xc4, 0x10, 0x8d, 0x43}},
     "JLP"},

    // GDfnEsia2WLAW5t8yx2X5j2mkfA74i5kwGdDuZHt7XmG
    {{{0xe2, 0x1e, 0x1f, 0x4d, 0x64, 0x60, 0xe8, 0xf5, 0xfb, 0xc8, 0x1c,
       0xfc, 0x0b, 0x79, 0x23, 0x1c, 0x42, 0xa0, 0xe3, 0xeb, 0x9a, 0x07,
       0xc7, 0x28, 0xaa, 0xc8, 0x8b, 0x1f, 0x59, 0xcc, 0x5f, 0x5f}},
     "CROWN"},

    // orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE
    {{{0x0c, 0x00, 0xd0, 0xaf, 0xeb, 0x86, 0x14, 0xda, 0x7f, 0x19, 0xab,
       0xa0, 0x2d, 0x40, 0xf1, 0x8c, 0x69, 0x25, 0x85, 0xf6, 0x50, 0x20,
       0xdf, 0xce, 0xd3, 0xd5, 0xe5, 0xf9, 0xa9, 0xc0, 0xc4, 0xe1}},
     "ORCA"},

    // METAewgxyPbgwsseH8T16a39CQ5VyVxZi9zXiDPY18m
    {{{0x05, 0x2e, 0xd3, 0x50, 0x10, 0xb8, 0x19, 0xff, 0x49, 0x14, 0xf4,
       0x7a, 0x31, 0x18, 0xc4, 0x2c, 0x98, 0xbf, 0x21, 0x0f, 0xd7, 0xe4,
       0x7d, 0x72, 0x23, 0x07, 0xb5, 0xc2, 0x49, 0x01, 0xa7, 0xba}},
     "MPLX"},

    // 5MAYDfq5yxtudAhtfyuMBuHZjgAbaS9tbEyEQYAhDS5y
    {{{0x40, 0x99, 0x26, 0x19, 0x06, 0xe4, 0xd9, 0x9a, 0x69, 0x26, 0x40,
       0x4c, 0xb7, 0x9d, 0x4a, 0x2d, 0xe5, 0x16, 0xb4, 0xae, 0xf1, 0x40,
       0xe4, 0xbf, 0x48, 0xd3, 0x5b, 0x4b, 0xa2, 0x26, 0x54, 0xe4}},
     "ACS"},

    // mb1eu7TzEc71KxDpsmsKoucSSuuoGLv1drys1oP2jh6
    {{{0x0b, 0x6c, 0x03, 0x23, 0x7c, 0xe5, 0xb7, 0x85, 0x33, 0x85, 0xaf,
       0x0e, 0x58, 0xd1, 0x04, 0xcf, 0xd3, 0x3b, 0x4f, 0x71, 0x06, 0x4f,
       0x89, 0xab, 0x55, 0x12, 0x7f, 0xdf, 0x27, 0x4c, 0x8c, 0x45}},
     "MOBILE"},

    // SHDWyBxihqiCj6YekG2GUr7wqKLeLAMK1gHZck9pL6y
    {{{0x06, 0x79, 0xdb, 0x01, 0xce, 0x2a, 0x84, 0xf7, 0x1c, 0x13, 0x9e,
       0x7c, 0x99, 0x42, 0xf6, 0xda, 0x3b, 0x33, 0x1f, 0xde, 0xc3, 0x31,
       0x9d, 0x02, 0xf8, 0x99, 0xeb, 0xa7, 0x01, 0x34, 0x73, 0x7e}},
     "SHDW"},

    // ETAtLmCmsoiEEKfNrHKJ2kYy3MoABhU6NQvpSfij5tDs
    {{{0xc7, 0xdc, 0x35, 0x52, 0xac, 0xd0, 0x85, 0xff, 0xa9, 0x89, 0xb8,
       0x1b, 0x21, 0xe5, 0xe0, 0xbc, 0xbc, 0xcb, 0xb1, 0xec, 0x87, 0x83,
       0x5f, 0x0d, 0xb1, 0x2f, 0xab, 0xba, 0xd6, 0x66, 0xdd, 0xf6}},
     "MEDIA"},

    // ATLASXmbPQxBUYbxPsV97usA3fPQYEqzQBUHgiFCUsXx
    {{{0x8c, 0x77, 0xf3, 0x66, 0x1d, 0x6b, 0x4a, 0x8e, 0xf3, 0x9d, 0xbc,
       0x53, 0x40, 0xee, 0xad, 0x8c, 0x3c, 0xbe, 0x0b, 0x45, 0x09, 0x98,
       0x40, 0xe8, 0x26, 0x3d, 0x87, 0x25, 0xb5, 0x87, 0xb0, 0x73}},
     "ATLAS"},

    // MNDEFzGvMt87ueuHvVU9VcTqsAP5b3fTGPsHuuPA5ey
    {{{0x05, 0x37, 0x99, 0x6f, 0x26, 0x99, 0x67, 0x4f, 0xb7, 0x08, 0x6e,
       0x46, 0x8f, 0xb3, 0x3b, 0x4f, 0xde, 0x14, 0x49, 0xf4, 0x7a, 0x8b,
       0xef, 0xd8, 0xb3, 0x42, 0xbf, 0x6b, 0x33, 0xcf, 0xf3, 0x72}},
     "MNDE"},

    // zebeczgi5fSEtbpfQKVZKCJ3WgYXxjkMUkNNx7fLKAF
    {{{0x0e, 0xc4, 0x9e, 0x1c, 0x77, 0xe7, 0x98, 0x28, 0xf9, 0xae, 0x8a,
       0x05, 0x1b, 0x66, 0x2e, 0x20, 0x88, 0xc7, 0x28, 0x06, 0x9c, 0xed,
       0xb7, 0x0f, 0xef, 0x85, 0x21, 0xb9, 0x4a, 0xcf, 0x74, 0xf8}},
     "ZBC"},

    // LFNTYraetVioAPnGJht4yNg2aUZFXR776cMeN9VMjXp
    {{{0x04, 0xee, 0x48, 0x96, 0x07, 0x8e, 0x4a, 0x49, 0x8b, 0x98, 0x82,
       0xe1, 0x9e, 0x08, 0x0f, 0x68, 0x57, 0x77, 0x65, 0x1e, 0x78, 0x6b,
       0x79, 0x16, 0xf0, 0x0b, 0x74, 0x64, 0x20, 0xe8, 0x62, 0x83}},
     "LFNTY"},

    // 5oVNBeEEQvYi1cX3ir8Dx5n1P7pdxydbGF2X4TxVusJm
    {{{0x47, 0x57, 0x89, 0x9f, 0xb8, 0xbe, 0xdb, 0xa2, 0x87, 0x78, 0xaa,
       0xcd, 0x67, 0xe5, 0x68, 0xe7, 0x34, 0x70, 0xcc, 0xe9, 0x0b, 0xcd,
       0x53, 0x2b, 0x6c, 0xb6, 0x18, 0x29, 0x76, 0x28, 0x82, 0x4e}},
     "INF"},

    // poLisWXnNRwC6oBu1vHiuKQzFjGL4XDSu4g9qjz9qVk
    {{{0x0c, 0x3e, 0xb1, 0xe2, 0xec, 0x6d, 0xbd, 0x1c, 0x0c, 0x8b, 0xd5,
       0x71, 0x71, 0x8d, 0xb6, 0xf6, 0x14, 0xd0, 0x40, 0xfa, 0xb4, 0x12,
       0xf1, 0x09, 0x1b, 0x66, 0xf1, 0x28, 0xde, 0xfb, 0x10, 0x53}},
     "POLIS"},

    // SCSuPPNUSypLBsV4darsrYNg4ANPgaGhKhsA3GmMyjz
    {{{0x06, 0x74, 0x76, 0x83, 0xac, 0x65, 0xf2, 0x3a, 0x11, 0xc4, 0xfc,
       0xc7, 0x8a, 0x2a, 0x1f, 0x80, 0x66, 0xcf, 0xd8, 0x71, 0x0a, 0x00,
       0xa9, 0xc6, 0xfd, 0xcf, 0x43, 0x25, 0x95, 0xd2, 0x3c, 0xdd}},
     "SCS"},

    // SLNDpmoWTVADgEdndyvWzroNL7zSi1dF9PC3xHGtPwp
    {{{0x06, 0x7d, 0x6a, 0xd4, 0x10, 0x20, 0xf0, 0x4f, 0xba, 0x7d, 0xa8,
       0xdd, 0x06, 0x76, 0xd3, 0x99, 0xd2, 0x6c, 0x41, 0x40, 0x63, 0x86,
       0xf0, 0x03, 0x9c, 0xa0, 0x06, 0x33, 0x03, 0xb4, 0xc5, 0x2b}},
     "SLND"},

    // GTH3wG3NErjwcf7VGCoXEXkgXSHvYhx5gtATeeM5JAS1
    {{{0xe5, 0x9a, 0x8d, 0xac, 0xb0, 0x4e, 0x22, 0x03, 0x58, 0x48, 0xe2,
       0x26, 0x29, 0x98, 0x86, 0xa3, 0x13, 0xe2, 0xa6, 0x36, 0xe9, 0x69,
       0x08, 0xd1, 0xfd, 0x5c, 0xd5, 0x5c, 0x87, 0xad, 0xb1, 0x16}},
     "WHALES"},

    // LSTxxxnJzKDFSLr4dUkPcmCf5VyryEqzPLz5j4bpxFp
    {{{0x04, 0xfa, 0xd4, 0x21, 0xc8, 0xf3, 0x76, 0xbe, 0xfc, 0xe3, 0xcd,
       0x69, 0x48, 0xcd, 0x63, 0xb6, 0xbe, 0xc5, 0xb8, 0xa3, 0x6f, 0x36,
       0x4d, 0xeb, 0x83, 0xa3, 0x93, 0xd7, 0x21, 0xb7, 0xd7, 0xef}},
     "LST"},

    // 3dgCCb15HMQSA4Pn3Tfii5vRk7aRqTH95LJjxzsG2Mug
    {{{0x27, 0x1c, 0x99, 0x48, 0x36, 0x6f, 0xba, 0x24, 0x59, 0x0f, 0xef,
       0xc9, 0x9d, 0x48, 0xca, 0xcb, 0xc2, 0x6e, 0xb3, 0xc4, 0x25, 0x1a,
       0x04, 0x5c, 0xf9, 0xab, 0xbe, 0x0d, 0x0e, 0x25, 0x1f, 0xd7}},
     "HXD"},

    // ATRLuHph8dxnPny4WSNW7fxkhbeivBrtWbY6BfB4xpLj
    {{{0x8c, 0x7d, 0xce, 0xe8, 0xb2, 0xf5, 0xb3, 0x77, 0xb2, 0x80, 0x64,
       0x51, 0x7d, 0xa0, 0x27, 0x36, 0xa6, 0x91, 0xf1, 0x94, 0xa9, 0xb2,
       0x73, 0x84, 0x4c, 0x1f, 0x46, 0x32, 0x44, 0xa1, 0xad, 0x9c}},
     "ATR"},

    // 3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh
    {{{0x23, 0x3c, 0xea, 0x47, 0x4d, 0x6c, 0xb5, 0x13, 0xda, 0xd4, 0x21,
       0xc8, 0x2e, 0x68, 0x1f, 0x80, 0xed, 0x75, 0x12, 0x45, 0x5d, 0xfb,
       0x91, 0xfc, 0x68, 0x36, 0x3b, 0x99, 0xd9, 0x15, 0x65, 0x82}},
     "WBTC"},

    // 7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs
    {{{0x66, 0xe5, 0x18, 0x8a, 0x13, 0x08, 0xa1, 0xdb, 0x90, 0xb6, 0xd3,
       0x1f, 0x3f, 0xbd, 0xca, 0x8c, 0x3d, 0xf2, 0x67, 0x8c, 0x81, 0x12,
       0xdf, 0xdd, 0x3d, 0x19, 0x2c, 0x5a, 0x3c, 0xc4, 0x57, 0xa8}},
     "ETH"},

    // octo82drBEdm8CSDaEKBymVn86TBtgmPnDdmE64PTqJ
    {{{0x0b, 0xf1, 0x4d, 0x34, 0xaf, 0xd8, 0x25, 0xbe, 0x9a, 0x6b, 0xcf,
       0xd2, 0xe5, 0x34, 0xfd, 0xaa, 0x1a, 0xf1, 0xd3, 0x73, 0xa3, 0xa5,
       0xd5, 0x80, 0xac, 0x78, 0x98, 0xf7, 0xb1, 0x71, 0xb2, 0x99}},
     "OTK"},

    // AURYydfxJib1ZkTir1Jn1J9ECYUtjb6rKQVmtYaixWPP
    {{{0x8c, 0xbf, 0x9f, 0xdb, 0xa8, 0x69, 0x1b, 0x67, 0xe3, 0x2e, 0xb5,
       0x7a, 0x78, 0x4b, 0x1c, 0xae, 0x27, 0x44, 0xc6, 0xfc, 0x03, 0xac,
       0x61, 0xe4, 0x50, 0xdd, 0x93, 0x31, 0xb9, 0xbd, 0xbb, 0x2e}},
     "AURY"},

    // SNSNkV9zfG5ZKWQs6x4hxvBRV6s8SqMfSGCtECDvdMd
    {{{0x06, 0x7f, 0xc2, 0x7a, 0xbc, 0xad, 0x2d, 0xf0, 0x7c, 0xc4, 0x04,
       0x37, 0x33, 0x0d, 0xa4, 0xfe, 0x88, 0x51, 0x68, 0x0a, 0xe2, 0xb2,
       0x42, 0xc2, 0xea, 0x1d, 0x86, 0xe2, 0xcf, 0xa1, 0x00, 0x64}},
     "SNS"},

    // 3bRTivrVsitbmCTGtqwp7hxXPsybkjn4XLNtPsHqa3zR
    {{{0x26, 0x88, 0xc7, 0x7a, 0x2a, 0x9c, 0x9a, 0xd1, 0x73, 0x18, 0x69,
       0x9d, 0xcb, 0x85, 0xb3, 0xd9, 0xa2, 0x37, 0x62, 0xc6, 0xe7, 0x15,
       0x6b, 0xc7, 0xf8, 0x3b, 0x30, 0x52, 0x95, 0x32, 0x93, 0xf2}},
     "LIKE"},

    // 947tEoG318GUmyjVYhraNRvWpMX7fpBTDQFBoJvSkSG3
    {{{0x77, 0xaa, 0x05, 0x5c, 0x1b, 0x14, 0x08, 0x41, 0x34, 0xbb, 0xe8,
       0x01, 0x36, 0xaa, 0x79, 0xc7, 0x7f, 0x2d, 0x90, 0x37, 0x62, 0x83,
       0x90, 0x36, 0x3a, 0xdc, 0x50, 0x2e, 0xc1, 0x98, 0xb0, 0x94}},
     "CHAT"},

    // FoXyMu5xwXre7zEoSvzViRk3nGawHUp9kUh97y2NDhcq
    {{{0xdb, 0xef, 0x5a, 0xa1, 0xe0, 0xf0, 0x04, 0x2e, 0xdd, 0x61, 0x9a,
       0x2f, 0x68, 0xfd, 0x3e, 0x4d, 0xf8, 0x33, 0x32, 0x5d, 0xd2, 0x03,
       0x7f, 0xcc, 0x6b, 0xb3, 0xb6, 0xed, 0x0c, 0xb7, 0x50, 0x8e}},
     "FOXY"},

    // 2FPyTwcZLUg1MDrwsyoP4D6s1tM7hAkHYRjkNb5w6Pxk
    {{{0x12, 0x8b, 0xcb, 0x64, 0x7d, 0x8b, 0xad, 0x1e, 0x72, 0x50, 0xe3,
       0xb8, 0x34, 0xbc, 0xfa, 0x9f, 0xd9, 0x86, 0xf4, 0xd4, 0x77, 0xd1,
       0xbb, 0xb9, 0x05, 0x4e, 0x60, 0x2b, 0x11, 0xeb, 0xe0, 0x61}},
     "soETH"},

    // HHjoYwUp5aU6pnrvN4s2pwEErwXNZKhxKGYjRJMoBjLw
    {{{0xf2, 0x04, 0xae, 0x4a, 0x20, 0x20, 0x16, 0xd4, 0xde, 0x45, 0x49,
       0x6d, 0x2b, 0x0b, 0xec, 0xaa, 0x65, 0x0f, 0x1e, 0x9a, 0x58, 0xc0,
       0x24, 0x26, 0xf4, 0x19, 0x01, 0x66, 0x48, 0x8f, 0x4d, 0x9c}},
     "PIP"},

    // MangoCzJ36AjZyKwVj3VnYU4GTonjfVEnJmvvWaxLac
    {{{0x05, 0x45, 0xd1, 0xee, 0x98, 0x05, 0x76, 0x4e, 0x58, 0xb3, 0xef,
       0x5b, 0xcb, 0x54, 0x17, 0x75, 0x17, 0xdf, 0xe7, 0x98, 0x0e, 0x6e,
       0x44, 0xe6, 0x7a, 0x62, 0x8b, 0xdb, 0x9d, 0x2a, 0x7b, 0xd1}},
     "MNGO"},

    // J2LWsSXx4r3pYbJ1fwuX5Nqo7PPxjcGPpUb2zHNadWKa
    {{{0xfc, 0xee, 0x53, 0x00, 0xd2, 0x06, 0x6f, 0x88, 0x1f, 0x95, 0xd9,
       0xd8, 0x0d, 0x06, 0xca, 0xb9, 0xe7, 0xc7, 0xf3, 0xa8, 0x71, 0xef,
       0x9a, 0xa4, 0x20, 0x82, 0x24, 0xaa, 0x81, 0xd2, 0xb7, 0x99}},
     "DPLN"},

    // UXPhBoR3qG4UCiGNJfV7MqhHyFqKN68g45GoYvAeL2M
    {{{0x07, 0x0d, 0x0b, 0x9b, 0xee, 0x96, 0x60, 0x9a, 0x69, 0xa1, 0x7a,
       0x10, 0x83, 0x37, 0x05, 0x37, 0x0f, 0xb1, 0x16, 0xa0, 0x6a, 0xdb,
       0x20, 0xd5, 0xef, 0xd8, 0x66, 0xe6, 0x80, 0x51, 0xc1, 0x32}},
     "UXP"},

    // Taki7fi3Zicv7Du1xNAWLaf6mRK7ikdn77HeGzgwvo4
    {{{0x06, 0xcf, 0x44, 0x2f, 0xd1, 0xea, 0x50, 0xd2, 0xb1, 0x86, 0x29,
       0x07, 0x92, 0x32, 0x39, 0x6c, 0x07, 0x5d, 0x29, 0xc1, 0xed, 0xa9,
       0x12, 0xd3, 0x8f, 0xd7, 0x50, 0x49, 0xf8, 0x27, 0xe3, 0xa3}},
     "TAKI"},

    // kinXdEcpDQeHPEuQnqmUgtYykqKGVFq6CeVX5iAHJq6
    {{{0x0b, 0x33, 0x38, 0xa0, 0xab, 0x2c, 0xc8, 0x41, 0xd5, 0xb0, 0x14,
       0xbc, 0x6a, 0x3c, 0xf7, 0x56, 0x29, 0x18, 0x74, 0xb3, 0x19, 0xc9,
       0x51, 0x7d, 0x9b, 0xbf, 0xa9, 0xe4, 0xe9, 0x66, 0x1e, 0xf9}},
     "KIN"},

    // H53UGEyBrB9easo9ego8yYk7o4Zq1G5cCtkxD3E3hZav
    {{{0xee, 0xc4, 0x1b, 0x61, 0x11, 0xa1, 0x43, 0x22, 0xdc, 0xa4, 0xc1,
       0x34, 0xe3, 0x35, 0xe9, 0x8e, 0xb8, 0x93, 0x42, 0x73, 0xe2, 0x9a,
       0x0b, 0xb1, 0x41, 0xbc, 0xc8, 0xdf, 0x57, 0x51, 0x09, 0x2f}},
     "MXM"},

    // HxhWkVpk5NS4Ltg5nij2G671CKXFRKPK8vy271Ub4uEK
    {{{0xfb, 0xff, 0xbe, 0x51, 0xe1, 0x73, 0x11, 0x60, 0xaa, 0x8e, 0xb9,
       0x1c, 0xbf, 0xe3, 0x1d, 0x8d, 0x67, 0xbd, 0x25, 0xcf, 0xc2, 0xee,
       0x12, 0x01, 0x97, 0x8e, 0x5c, 0x1a, 0xb3, 0x22, 0xfc, 0xcc}},
     "HXRO"},

    // 7Q2afV64in6N6SeZsAAB81TJzwDoD6zpqmHkzi9Dcavn
    {{{0x5f, 0x0c, 0x44, 0x63, 0x18, 0xab, 0x10, 0xc9, 0x5f, 0x40, 0x94,
       0x95, 0x85, 0x70, 0xcd, 0x05, 0x74, 0x65, 0xa5, 0x4d, 0xab, 0x14,
       0xd9, 0xdd, 0xe3, 0x48, 0x1a, 0x86, 0xfe, 0xd5, 0xfc, 0xcb}},
     "JSOL"},

    // A1KLoBrKBde8Ty9qtNQUtq3C2ortoC3u7twggz7sEto6
    {{{0x85, 0xcd, 0xeb, 0xc2, 0x05, 0xdd, 0xdf, 0x95, 0xb8, 0x82, 0x00,
       0xab, 0xa0, 0xac, 0x9b, 0xcb, 0xb7, 0x80, 0x96, 0x32, 0x4e, 0x27,
       0x6f, 0xce, 0x85, 0xd6, 0x3c, 0x69, 0x21, 0x1f, 0x08, 0x45}},
     "USDY"},

    // HzwqbKZw8HxMN6bF2yFZNrht3c2iXXzpKcFu7uBEDKtr
    {{{0xfc, 0x93, 0x1a, 0x2b, 0x58, 0xcd, 0x23, 0xdb, 0x2d, 0x91, 0xd2,
       0x96, 0xd9, 0x65, 0x05, 0xa0, 0x6f, 0x80, 0x94, 0x20, 0x83, 0xf8,
       0x41, 0xe8, 0xa8, 0x87, 0xf1, 0x38, 0xac, 0x03, 0x04, 0x37}},
     "EURC"},

    // SHARKSYJjqaNyxVfrpnBN9pjgkhwDhatnMyicWPnr1s
    {{{0x06, 0x79, 0xcb, 0x8c, 0x7a, 0x61, 0xdf, 0xdd, 0x5b, 0x59, 0x21,
       0x20, 0xff, 0x5c, 0xfc, 0x5b, 0x1e, 0xe8, 0xe3, 0x7b, 0x57, 0x37,
       0x2c, 0xdb, 0xa4, 0x00, 0xd2, 0x37, 0x39, 0x92, 0x94, 0xde}},
     "SHARK"},

    // AFbX8oGjGpmVFywbVouvhQSRmiW2aR1mohfahi4Y2AdB
    {{{0x89, 0x76, 0x58, 0x55, 0x7d, 0x21, 0x17, 0x22, 0xba, 0x67, 0x8a,
       0xd9, 0x92, 0x76, 0xeb, 0x14, 0xd9, 0x56, 0x7f, 0x0a, 0x79, 0x2e,
       0x3b, 0xa7, 0x0c, 0x89, 0x47, 0x85, 0xc7, 0x42, 0xbf, 0xae}},
     "GST"},

    // FtgGSFADXBtroxq8VCausXRr2of47QBf5AS1NtZCu4GD
    {{{0xdd, 0x40, 0xa2, 0xf6, 0xf4, 0x23, 0xe4, 0xc3, 0x99, 0x0a, 0x83,
       0xea, 0xc3, 0xd9, 0xd9, 0xc1, 0xfe, 0x62, 0x5b, 0x36, 0xcb, 0xc5,
       0xe4, 0xa6, 0xd5, 0x53, 0x54, 0x45, 0x52, 0xa8, 0x67, 0xee}},
     "BRZ"},

    // FLUXBmPhT3Fd1EDVFdg46YREqHBeNypn1h4EbnTzWERX
    {{{0xd5, 0x00, 0xc5, 0x11, 0xdc, 0xfe, 0x06, 0x75, 0xf9, 0xf5, 0x5c,
       0x1f, 0x40, 0x8c, 0x78, 0x33, 0xbe, 0x62, 0x0f, 0xdc, 0x02, 0xdb,
       0x6d, 0x05, 0xed, 0x0f, 0xa3, 0x64, 0x86, 0xab, 0x4a, 0xfa}},
     "FLUXB"},

    // AMUwxPsqWSd1fbCGzWsrRKDcNoduuWMkdR38qPdit8G8
    {{{0x8a, 0xf8, 0x66, 0x1b, 0xa2, 0x26, 0x13, 0x73, 0x3b, 0x7c, 0x80,
       0x25, 0x12, 0x85, 0x97, 0x49, 0x7d, 0xea, 0x99, 0x52, 0x50, 0x6b,
       0x2e, 0x1b, 0x48, 0x4d, 0xc8, 0x40, 0xbe, 0xfe, 0x83, 0xf1}},
     "AMU"},

    // NFTUkR4u7wKxy9QLaX2TGvd9oZSWoMo4jqSJqdMb7Nk
    {{{0x05, 0x71, 0x8b, 0x04, 0x57, 0x23, 0x12, 0xd7, 0x3a, 0xa7, 0x1d,
       0xea, 0xec, 0x43, 0xc8, 0x9d, 0x77, 0x84, 0x4b, 0x0b, 0x7f, 0xf9,
       0xe3, 0xe7, 0x2d, 0xa8, 0x51, 0x01, 0x82, 0x62, 0x74, 0x55}},
     "BLOCK"},

    // StepAscQoEioFxxWGnh2sLBDFp9d8rvKz2Yp39iDpyT
    {{{0x06, 0xa1, 0xec, 0x5b, 0xd8, 0x2a, 0xd9, 0xc0, 0x32, 0xa9, 0xf7,
       0xd4, 0x66, 0xba, 0x2c, 0x72, 0x8b, 0x0e, 0xf3, 0x6a, 0x8b, 0x77,
       0x3e, 0xd2, 0x19, 0xd6, 0x96, 0x50, 0xd3, 0x47, 0x2b, 0xd6}},
     "STEP"},

    // GENEtH5amGSi8kHAtQoezp1XEXwZJ8vcuePYnXdKrMYz
    {{{0xe2, 0x4b, 0xde, 0xae, 0xff, 0xa0, 0x4f, 0x43, 0xb8, 0x77, 0x1a,
       0x42, 0x0b, 0x80, 0x06, 0x1c, 0xf0, 0x93, 0x26, 0x0d, 0xb2, 0x9a,
       0xc9, 0xc8, 0xea, 0xd6, 0x50, 0x58, 0xa9, 0x7f, 0x78, 0x57}},
     "GENE"},

    // BiDB55p4G3n1fGhwKFpxsokBMqgctL4qnZpDH1bVQxMD
    {{{0x9f, 0x23, 0x72, 0x7b, 0xb4, 0xe0, 0x7e, 0x5c, 0xd8, 0x8e, 0xb5,
       0x18, 0x1a, 0xab, 0xc6, 0xe9, 0xe8, 0x7f, 0x53, 0xd1, 0x36, 0xbd,
       0x29, 0xfa, 0x5b, 0x67, 0xaf, 0x7c, 0x6e, 0x81, 0x9f, 0xe8}},
     "DIO"},

    // 6dKCoWjpj5MFU5gWDEFdpUUeBasBLK3wLEwhUzQPAa1e
    {{{0x53, 0x97, 0xed, 0x2f, 0x2a, 0x5d, 0x3f, 0x90, 0x26, 0xb5, 0x63,
       0x60, 0x02, 0x91, 0x9b, 0x46, 0x61, 0x96, 0x80, 0x24, 0x7b, 0xc7,
       0x2f, 0x07, 0xc5, 0xaf, 0x48, 0x91, 0x0d, 0x42, 0x7d, 0xb1}},
     "CHEX"},

    // a11bdAAuV8iB2fu7X6AxAvDTo1QZ8FXB3kk5eecdasp
    {{{0x08, 0x74, 0x2d, 0xa7, 0x7f, 0x53, 0x2c, 0xb2, 0x33, 0x74, 0x02,
       0xe2, 0xab, 0x66, 0x18, 0x7b, 0x63, 0xa2, 0x90, 0x7c, 0x9a, 0x62,
       0x10, 0x7d, 0xab, 0x70, 0x13, 0xa2, 0x8d, 0xeb, 0x46, 0x57}},
     "ABR"},

    // AT79ReYU9XtHUTF5vM6Q4oa9K8w7918Fp5SU7G1MDMQY
    {{{0x8c, 0x69, 0x3b, 0x59, 0xc0, 0xf9, 0xe7, 0x25, 0x7e, 0xbf, 0xf1,
       0x76, 0xe0, 0xbb, 0x1b, 0xde, 0xf1, 0x54, 0x0e, 0x0c, 0x24, 0xe6,
       0xa3, 0x4e, 0x79, 0xc9, 0x59, 0xd1, 0x7d, 0x50, 0x95, 0x05}},
     "SPDR"},

    // iotEVVZLEywoTn1QdwNPddxPWszn3zFhEot3MfL9fns
    {{{0x0a, 0xb5, 0xd3, 0x06, 0x1b, 0x5b, 0x03, 0x3c, 0xd8, 0x4b, 0xe6,
       0x6e, 0x60, 0xac, 0xc1, 0xac, 0x75, 0x68, 0xf4, 0x61, 0xfb, 0x39,
       0x74, 0xd3, 0xa5, 0xb6, 0xaa, 0x2f, 0xd5, 0x24, 0x01, 0xec}},
     "IOT"},

    // CKaKtYvz6dKPyMvYq9Rh3UBrnNqYZAyd7iF4hJtjUvks
    {{{0xa8, 0x32, 0xb1, 0x34, 0x7f, 0x65, 0x93, 0x2a, 0xa5, 0xa8, 0xb8,
       0xe3, 0xb6, 0xf7, 0x85, 0x4a, 0x29, 0x72, 0x15, 0x7d, 0x03, 0x75,
       0x09, 0x7d, 0x59, 0x9e, 0xab, 0xac, 0x96, 0x85, 0xa9, 0x5c}},
     "GARI"},

    // xxxxa1sKNGwFtw2kFn8XauW9xq8hBZ5kVtcSesTT9fW
    {{{0x0e, 0x56, 0x39, 0x5e, 0x3c, 0x86, 0x01, 0x43, 0x80, 0x2e, 0x9b,
       0x94, 0xa0, 0x2c, 0xc6, 0xd0, 0x4f, 0x75, 0xfe, 0xc7, 0x2a, 0x3f,
       0xbb, 0x71, 0x52, 0x68, 0x35, 0x5e, 0x0c, 0xd7, 0xcd, 0x89}},
     "SLIM"},

    // LAinEtNLgpmCP9Rvsf5Hn8W6EhNiKLZQti1xfWMLy6X
    {{{0x04, 0xe9, 0x06, 0xb5, 0x1e, 0x90, 0x97, 0x2f, 0xd4, 0xcd, 0x69,
       0x94, 0x3a, 0x88, 0x61, 0xda, 0xc5, 0x79, 0x3f, 0xa7, 0x3c, 0xf7,
       0x7b, 0x2c, 0xb3, 0xd7, 0x63, 0x23, 0x5f, 0x83, 0x07, 0x78}},
     "laineSOL"},

    // 7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj
    {{{0x62, 0x71, 0xcb, 0x71, 0x19, 0x47, 0x6b, 0x9d, 0xce, 0x00, 0xd8,
       0x15, 0xc8, 0xff, 0x31, 0x5f, 0xc8, 0xbf, 0x7d, 0x28, 0x48, 0x63,
       0x3d, 0x34, 0x94, 0x2a, 0xdf, 0xd5, 0x35, 0xf2, 0xde, 0xfe}},
     "stSOL"},

    // 6gnCPhXtLnUD76HjQuSYPENLSZdG8RvDB1pTLM5aLSJA
    {{{0x54, 0x7b, 0x30, 0x9e, 0xac, 0xe6, 0x70, 0xa9, 0xaf, 0x4c, 0x6d,
       0xa1, 0x24, 0x02, 0xdd, 0xbb, 0xc6, 0x0d, 0x43, 0xc1, 0x0e, 0x2c,
       0x17, 0x7b, 0x95, 0x33, 0xbd, 0xbc, 0x18, 0x88, 0x57, 0x6f}},
     "BSKT"},

    // FANoyuAQZx7AHCnxqsLeWq6te63F6zs6ENkbncCyYUZu
    {{{0xd2, 0x6a, 0x81, 0x42, 0x2f, 0xbf, 0x26, 0x6c, 0xfb, 0xcb, 0xa8,
       0xe5, 0x5f, 0xd7, 0xd8, 0xc9, 0xf3, 0x81, 0xde, 0x3f, 0x5e, 0x15,
       0x0a, 0x97, 0x08, 0x85, 0xe2, 0x5b, 0x9a, 0xb6, 0xbd, 0xb8}},
     "FAN"},

    // yomFPUqz1wJwYSfD5tZJUtS3bNb8xs8mx9XzBv8RL39
    {{{0x0e, 0x8d, 0x66, 0x79, 0x15, 0xb5, 0x29, 0xb5, 0xf5, 0x74, 0x4c,
       0xd9, 0x21, 0x9f, 0xae, 0x07, 0x18, 0xc8, 0x74, 0x02, 0x66, 0x91,
       0xac, 0x8e, 0xd2, 0x41, 0x3c, 0x4c, 0x61, 0x1c, 0x72, 0x78}},
     "YOM"},

    // CvB1ztJvpYQPvdPBePtRzjL4aQidjydtUz61NWgcgQtP
    {{{0xb1, 0x0f, 0xaa, 0x62, 0x56, 0x79, 0xd8, 0xf1, 0x1e, 0x57, 0x1a,
       0x96, 0x7e, 0xe2, 0x18, 0x67, 0xb2, 0x0c, 0xe9, 0x5b, 0xe8, 0xc3,
       0x7f, 0x6b, 0xe4, 0xa3, 0x99, 0x88, 0xff, 0xb5, 0x4a, 0x48}},
     "EPCT"},

    // GFX1ZjR2P15tmrSwow6FjyDYcEkoFb4p4gJCpLBjaxHD
    {{{0xe2, 0x97, 0x5e, 0x09, 0x79, 0x97, 0x18, 0x8b, 0x8c, 0x83, 0xcf,
       0x5b, 0x64, 0xf2, 0x8f, 0xf4, 0x2b, 0x1a, 0xe5, 0x79, 0xb1, 0xb6,
       0x74, 0x78, 0x57, 0xbf, 0x72, 0x21, 0x50, 0xde, 0x7f, 0xb0}},
     "GOFX"},

    // DFL1zNkaGPWm1BqAVqRjCZvHmwTFrEaJtbzJWgseoNJh
    {{{0xb5, 0xf7, 0xe0, 0x89, 0x66, 0xfa, 0x2f, 0x99, 0x7a, 0xbc, 0x90,
       0xd7, 0xa7, 0xcd, 0xe1, 0xbc, 0x73, 0x3f, 0x56, 0x7b, 0x9e, 0xaf,
       0xc3, 0x00, 0x7e, 0x80, 0xa3, 0x17, 0x47, 0x26, 0xb6, 0xf6}},
     "DFL"},

    // BLZEEuZUBVqFhj8adcCFPJvPVCiCyVmh3hkJMrU8KuJA
    {{{0x99, 0x97, 0x58, 0x62, 0xe4, 0xe3, 0x73, 0xb0, 0x06, 0x36, 0x04,
       0xe0, 0x3e, 0xbc, 0xed, 0x38, 0xda, 0x70, 0x60, 0x83, 0x92, 0x38,
       0xfb, 0x70, 0x01, 0xa9, 0x25, 0xfd, 0x85, 0x75, 0x6c, 0x93}},
     "BLZE"},

    // 31k88G5Mq7ptbRDf3AM13HAq6wRQHXHikR8hik7wPygk
    {{{0x1d, 0xe8, 0x22, 0x0d, 0x15, 0x41, 0x4f, 0x8b, 0xe6, 0x88, 0x94,
       0x9b, 0xb1, 0xa2, 0xe8, 0x53, 0xc4, 0x5d, 0x49, 0xfb, 0x9c, 0x17,
       0xb7, 0x0f, 0xf4, 0x25, 0x0c, 0x82, 0xc0, 0x51, 0x8c, 0xb1}},
     "GP"},

    // EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm
    {{{0xc5, 0xf9, 0xfb, 0x32, 0xf4, 0x91, 0x11, 0xab, 0x20, 0xc3, 0x3f,
       0x25, 0x98, 0xfc, 0x83, 0x6c, 0x11, 0x3e, 0x29, 0x18, 0x81, 0xac,
       0x21, 0xee, 0x29, 0x16, 0x93, 0x94, 0x01, 0x12, 0x44, 0xe4}},
     "WIF"},

    // DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263
    {{{0xbc, 0x07, 0xc5, 0x6e, 0x60, 0xad, 0x3d, 0x3f, 0x17, 0x73, 0x82,
       0xea, 0xc6, 0x54, 0x8f, 0xba, 0x1f, 0xd3, 0x2c, 0xfd, 0x90, 0xca,
       0x02, 0xb3, 0xe7, 0xcf, 0xa1, 0x85, 0xfd, 0xce, 0x73, 0x98}},
     "BONK"},

    // 7atgF8KQo4wJrD5ATGX7t1V2zVvykPJbFfNeVf1icFv1
    {{{0x61, 0xd4, 0xb8, 0x1c, 0xd9, 0x57, 0xf4, 0xa4, 0x29, 0x2d, 0x8f,
       0xbd, 0xd5, 0x0e, 0xa9, 0xd4, 0xe9, 0x8b, 0x16, 0xf3, 0x23, 0x35,
       0xa3, 0xae, 0x8c, 0xb3, 0x37, 0xf8, 0x79, 0x45, 0x91, 0x82}},
     "CWIF"},

    // WENWENvqqNya429ubCdR81ZmD69brwQaaBYY6p3LCpk
    {{{0x07, 0x7c, 0xf6, 0x3a, 0x56, 0xff, 0x0a, 0xfb, 0x12, 0x4f, 0x6f,
       0x68, 0x87, 0x5a, 0x02, 0xad, 0xce, 0x4e, 0x32, 0x0b, 0xbf, 0xcc,
       0x10, 0x72, 0xe6, 0x7a, 0x0a, 0x4f, 0xfa, 0x46, 0xc2, 0x95}},
     "WEN"},

    // HhJpBhRRn4g56VsyLuT8DL5Bv31HkXqsrahTTUCZeZg4
    {{{0xf8, 0x0e, 0x5d, 0x70, 0xb7, 0x83, 0x02, 0xf8, 0xd6, 0x2d, 0x34,
       0xaa, 0x70, 0xf1, 0xb5, 0xb9, 0x1f, 0xee, 0xde, 0xa3, 0x30, 0xd9,
       0xbe, 0x32, 0x69, 0xca, 0xeb, 0x8e, 0x9a, 0x38, 0x74, 0xc1}},
     "MYRO"},

    // 7GCihgDB8fe6KNjn2MYtkzZcRjQy3t9GHdC8uHYmW2hr
    {{{0x5d, 0x0b, 0x15, 0x9a, 0xff, 0xcb, 0xcc, 0xf1, 0x65, 0xc0, 0x9b,
       0xc2, 0xf5, 0xd4, 0xba, 0xfb, 0x4a, 0xa6, 0x34, 0x5a, 0xf7, 0x93,
       0xb9, 0xb3, 0x22, 0x2d, 0xaa, 0x40, 0x29, 0x3a, 0x95, 0x0d}},
     "POPCAT"},

    // 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
    {{{0x67, 0x52, 0x05, 0x5c, 0x20, 0xb3, 0xe9, 0xd8, 0x74, 0x66, 0x56,
       0xdd, 0xf7, 0x38, 0x55, 0x50, 0x7f, 0x87, 0xab, 0x6d, 0x87, 0x52,
       0x3e, 0x4c, 0x76, 0xa7, 0xfa, 0x36, 0x09, 0x6a, 0x99, 0xeb}},
     "SAMO"},

    // ukHH6c7mMyiWCf1b9pnWe25TSpkDDt3H5pQZgZ74J82
    {{{0x0d, 0x83, 0x23, 0xc0, 0x76, 0xf0, 0xe2, 0x87, 0x18, 0xca, 0x60,
       0xd7, 0x7e, 0x6b, 0x39, 0xce, 0xe8, 0xf2, 0x3f, 0x43, 0xcf, 0xc4,
       0xff, 0x1f, 0x58, 0x52, 0xb8, 0xfc, 0x1b, 0x94, 0xa2, 0x93}},
     "BOME"},

    // 3psH1Mj1f7yUfaD5gh6Zj7epE8hhrMkMETgv5TshQA4o
    {{{0x29, 0xfa, 0x84, 0xe3, 0x98, 0x00, 0xdd, 0x05, 0xc3, 0x0e, 0x17,
       0x4b, 0x61, 0xa2, 0x32, 0xe5, 0x0f, 0xad, 0xf1, 0xd4, 0xeb, 0x86,
       0x90, 0xdb, 0x78, 0x35, 0x45, 0x0c, 0x42, 0x4b, 0x3b, 0xf8}},
     "boden"},

    // BZLbGTNCSFfoth2GYDtwr7e4imWzpR5jqcUuGEwr646K
    {{{0x9c, 0xdd, 0x9b, 0x46, 0x6a, 0xf3, 0x24, 0xc5, 0x8b, 0x65, 0x3f,
       0x6e, 0xac, 0x5e, 0x78, 0xf7, 0x48, 0xe5, 0x57, 0x78, 0xca, 0xed,
       0x00, 0xa9, 0x0d, 0x61, 0xe7, 0x0c, 0x06, 0x15, 0x87, 0xf8}},
     "IO"},

    // 7BgBvyjrZX1YKz4oh9mjb8ZScatkkwb8DzFx7LoiVkM3
    {{{0x5b, 0xe2, 0x3d, 0x7c, 0x88, 0x1e, 0x44, 0x5a, 0x93, 0x87, 0xe6,
       0x5e, 0xe9, 0xb2, 0xba, 0x25, 0xa1, 0xff, 0xa3, 0x42, 0x90, 0x08,
       0xb5, 0x91, 0x78, 0x4f, 0xbe, 0x63, 0x00, 0x09, 0x1d, 0x06}},
     "SLERF"},

    // KMNo3nJsBXfcpJTVhZcXLW7RmTwTt4GVFE7suUBo9sS
    {{{0x04, 0xb3, 0x7e, 0x56, 0x63, 0xeb, 0xe9, 0x15, 0xd8, 0x10, 0xb2,
       0x0f, 0x0a, 0x0e, 0x3e, 0x0d, 0x2d, 0x46, 0x1d, 0x1e, 0xfa, 0xb2,
       0xd6, 0x00, 0xf6, 0xa3, 0x6b, 0x14, 0x1e, 0x1d, 0xc4, 0x3d}},
     "KMNO"},

    // MEW1gQWJ3nEXg2qgERiKu7FAFj79PHvQVREQUzScPP5
    {{{0x05, 0x2e, 0xe1, 0x83, 0x38, 0x96, 0x96, 0x9f, 0x8c, 0xd1, 0xcd,
       0x46, 0x83, 0x18, 0xc5, 0x98, 0xc7, 0xe0, 0x58, 0x96, 0x07, 0x4a,
       0x59, 0x1c, 0x2a, 0xe0, 0x98, 0x60, 0x2f, 0x16, 0x80, 0x00}},
     "MEW"},

    // NYANpAp9Cr7YarBNrby7Xx4xU6No6JKTBuohNA3yscP
    {{{0x05, 0x84, 0x6e, 0x7c, 0x90, 0x14, 0x4a, 0x9b, 0xb8, 0xe9, 0x53,
       0xc8, 0xf8, 0x43, 0x7a, 0xa8, 0xd4, 0x6f, 0x5d, 0x64, 0x88, 0x88,
       0x91, 0x53, 0x63, 0x34, 0x54, 0x23, 0xad, 0x7b, 0x83, 0xcc}},
     "NYAN"},

    // WskzsKqEW3ZsmrhPAevfVZb6PuuLzWov9mJWZsfDePC
    {{{0x07, 0xa7, 0x3c, 0x83, 0x03, 0x08, 0x33, 0xb6, 0x02, 0x41, 0x65,
       0xe3, 0x25, 0x64, 0x1c, 0xa8, 0x37, 0xf9, 0x5f, 0x5b, 0xfe, 0xb1,
       0x5a, 0xa2, 0xde, 0x75, 0xe3, 0xea, 0x4c, 0x51, 0xb8, 0x3b}},
     "PUNDU"},

    // Saber2gLauYim4Mvftnrasomsv6NvAuncvMEZwcLpD1
    {{{0x06, 0x8d, 0x82, 0x4d, 0x56, 0xf0, 0xee, 0xbb, 0x75, 0x66, 0xe6,
       0xee, 0x1d, 0x65, 0xa9, 0xd2, 0x60, 0xff, 0x50, 0x9a, 0x4b, 0x5c,
       0x69, 0xb6, 0x26, 0x9a, 0xd6, 0x4d, 0xe3, 0xcd, 0x50, 0xbc}},
     "SBR"},

    // 2wme8EVkw8qsfSk2B3QeX4S64ac6wxHPXb3GrdckEkio
    {{{0x1c, 0xe3, 0x86, 0x7b, 0x2c, 0x5d, 0x1d, 0xb6, 0x24, 0x66, 0x84,
       0xe3, 0x4b, 0x41, 0x76, 0xff, 0x98, 0x56, 0x78, 0xb0, 0xdb, 0x29,
       0x96, 0x85, 0xd4, 0x11, 0xf2, 0x87, 0x63, 0xca, 0x57, 0x9c}},
     "sols"},

    // 8wXtPeU6557ETkp9WHFY1n1EcU6NxDvbAggHGsMYiHsB
    {{{0x75, 0xfa, 0x18, 0x5a, 0xaf, 0xf1, 0xc7, 0x81, 0xb0, 0x72, 0x69,
       0xa4, 0xdf, 0xd7, 0x84, 0x9a, 0xdd, 0x90, 0xa6, 0xdb, 0x20, 0x7b,
       0xf6, 0x1c, 0xff, 0x50, 0x6c, 0x9b, 0x3d, 0x52, 0x53, 0x76}},
     "GME"},

    // SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt
    {{{0x06, 0x83, 0x10, 0x86, 0x1a, 0x98, 0x32, 0x7d, 0x05, 0x50, 0x57,
       0x4d, 0x84, 0x41, 0x8a, 0xa6, 0xe1, 0x0c, 0x33, 0x52, 0xdd, 0xaa,
       0x7f, 0xd7, 0xf5, 0x81, 0x52, 0xcc, 0xee, 0xb2, 0x38, 0x87}},
     "SRM"},

    // 7iT1GRYYhEop2nV1dyCwK2MGyLmPHq47WhPGSwiqcUg5
    {{{0x63, 0xc4, 0x56, 0x94, 0xcb, 0x85, 0xe8, 0x43, 0xbb, 0x0b, 0xac,
       0x31, 0x2f, 0xc3, 0x5f, 0xbc, 0xbf, 0x58, 0x17, 0xcb, 0x43, 0x48,
       0x48, 0xc8, 0xd6, 0x1c, 0x73, 0xb2, 0xfa, 0x62, 0xb3, 0xbe}},
     "ANALOS"},

    // AujTJJ7aMS8LDo3bFzoyXDwT3jBALUbu4VZhzZdTZLmG
    {{{0x93, 0x3b, 0x62, 0xfa, 0xe4, 0x36, 0x57, 0xcf, 0xc3, 0xaa, 0xca,
       0x34, 0xae, 0xfb, 0x49, 0xf3, 0x91, 0x3c, 0x0a, 0x61, 0xda, 0x49,
       0x50, 0x57, 0x28, 0x6a, 0xd1, 0x1d, 0x35, 0x2f, 0xb5, 0x53}},
     "BEER"},

    // AHW5N8iqZobTcBepkSJzZ61XtAuSzBDcpxtrLG6KUKPk
    {{{0x89, 0xf3, 0x59, 0xcc, 0x0b, 0x2e, 0x25, 0x66, 0x65, 0x27, 0x84,
       0xa0, 0x59, 0x41, 0xb5, 0xb4, 0x80, 0x82, 0xaf, 0xe7, 0xa7, 0x79,
       0x88, 0x2a, 0x69, 0xbc, 0x63, 0x23, 0xec, 0x18, 0xd3, 0x67}},
     "BENDOG"},

    // 4Cnk9EPnW5ixfLZatCPJjDB1PUtcRpVVgTQukm9epump
    {{{0x2f, 0x98, 0x2c, 0x21, 0x9d, 0x58, 0x1e, 0x23, 0xf4, 0x10, 0xf3,
       0x20, 0xee, 0x59, 0xa5, 0x43, 0xda, 0xdd, 0xa9, 0xd7, 0x92, 0x5d,
       0x69, 0x95, 0xa8, 0x89, 0x82, 0xeb, 0x5e, 0x63, 0xf3, 0x9f}},
     "DADDY"},

    // ED5nyyWEzpPPiWimP8vYm7sD7TD3LAt3Q3gRTWHzPJBY
    {{{0xc4, 0x40, 0x51, 0xa9, 0x11, 0xb5, 0x4c, 0x7e, 0xcf, 0xfc, 0x7e,
       0xe0, 0xb0, 0xa4, 0x0a, 0xf4, 0x8b, 0x32, 0x8a, 0xe7, 0x55, 0xa9,
       0x95, 0x33, 0xc8, 0x40, 0x2c, 0xb2, 0x6d, 0xf4, 0x38, 0x07}},
     "MOODENG"},

    // 2qEHjDLDLbuBgRYvsxhc5D6uDWAivNFZGan56P1tpump
    {{{0x1b, 0x36, 0x97, 0x4c, 0xca, 0xbe, 0x2b, 0xdb, 0x37, 0xc7, 0xad,
       0xa3, 0xc3, 0x33, 0x45, 0x12, 0x6f, 0x97, 0x3d, 0xa0, 0xb5, 0x43,
       0x00, 0xc1, 0xae, 0x06, 0xb8, 0x80, 0xc2, 0x4a, 0xac, 0xff}},
     "Pnut"},

    // CzLSujWBLFsSjncfkh59rUFqvafWcY5tzedWJSuypump
    {{{0xb2, 0x20, 0xa6, 0x99, 0x04, 0xb6, 0xee, 0xd8, 0x8a, 0x0b, 0xe9,
       0x89, 0x14, 0x29, 0x80, 0xfc, 0xd1, 0xa8, 0x1e, 0x85, 0x47, 0x33,
       0x32, 0x83, 0x26, 0x31, 0xcb, 0xb6, 0x2e, 0x11, 0x62, 0x8f}},
     "GOAT"},

    // J3NKxxXZcnNiMjKw9hYb2K4LUxgwB6t1FtPtQVsv3KFr
    {{{0xfd, 0x31, 0xf4, 0x30, 0x0c, 0xa5, 0xb0, 0x0a, 0x3e, 0x82, 0x47,
       0xb6, 0xaa, 0xd5, 0x4d, 0x9f, 0x7b, 0xd6, 0x1b, 0x26, 0x7f, 0x60,
       0x89, 0x98, 0xcc, 0x5f, 0xe9, 0xf2, 0xd9, 0x7c, 0x3d, 0x45}},
     "SPX"},

    // Df6yfrKC8kZE3KNkrHERKzAetSxbrWeniQfyJY4Jpump
    {{{0xbc, 0x0f, 0x12, 0x78, 0x80, 0xa7, 0xa2, 0x07, 0xb3, 0x45, 0x36,
       0x9b, 0xa6, 0x71, 0x75, 0xbd, 0xb7, 0xf7, 0x98, 0x13, 0x45, 0x71,
       0xeb, 0x5d, 0xe8, 0x17, 0xce, 0xdb, 0xbb, 0xd5, 0xdd, 0xff}},
     "CHILLGUY"},

    // GJAFwWjJ3vnTsrQVabjBVK2TYB1YtRCQXRDfDgUnpump
    {{{0xe3, 0x44, 0xa5, 0x2e, 0x00, 0x19, 0x39, 0x9b, 0xef, 0x02, 0xf7,
       0x62, 0xe1, 0xed, 0x8c, 0xc0, 0x5f, 0x8c, 0xfd, 0xa7, 0xbd, 0xa5,
       0x57, 0x96, 0xb9, 0xb9, 0x84, 0x1a, 0xaf, 0xe0, 0x06, 0x3f}},
     "ACT"},

    // A8C3xuqscfmyLrte3VmTqrAq8kgMASius9AFNANwpump
    {{{0x87, 0x90, 0xbe, 0x57, 0x84, 0x2c, 0x24, 0x8c, 0x85, 0x74, 0xd9,
       0x7a, 0x70, 0x39, 0x77, 0x88, 0x32, 0x41, 0x7e, 0xdc, 0xaf, 0xc4,
       0x6e, 0x6d, 0x2b, 0x04, 0x00, 0x83, 0xfd, 0x2e, 0x87, 0x0f}},
     "FWOG"},

    // 8x5VqbHA8D7NkD52uNuS5nnt3PwA8pLD34ymskeSo2Wn
    {{{0x76, 0x1d, 0xd6, 0x86, 0x55, 0x8c, 0xa0, 0x1d, 0xf7, 0x5a, 0x12,
       0x0d, 0x2a, 0x50, 0xdd, 0x8f, 0xf7, 0xb2, 0xde, 0xe5, 0x0d, 0xf5,
       0xf2, 0x0d, 0xec, 0x8d, 0x49, 0x23, 0x19, 0xb5, 0xdf, 0x83}},
     "ZEREBRO"},

    // HeLp6NuQkmYB4pYWo2zYs22mESHXPQYzXbB8n4V98jwC
    {{{0xf7, 0x4b, 0xe1, 0xd7, 0x6a, 0xb9, 0xa6, 0xc2, 0xbe, 0x49, 0x99,
       0x66, 0x3f, 0xc6, 0xa0, 0xe1, 0x99, 0x74, 0x00, 0x0e, 0x83, 0x6e,
       0xf3, 0x0c, 0x5b, 0x62, 0x86, 0xf4, 0x2c, 0x02, 0x0f, 0x87}},
     "ai16z"},

    // GJtJuWD9qYcCkrwMBmtY1tpapV1sKfB2zUv9Q4aqpump
    {{{0xe3, 0x74, 0x31, 0x4d, 0xd6, 0xca, 0xa0, 0xbc, 0xb6, 0x2e, 0x9a,
       0xcd, 0xc2, 0x87, 0xe7, 0xc5, 0x8f, 0x8a, 0x58, 0xa5, 0xfd, 0x33,
       0xc2, 0x68, 0x21, 0x82, 0xc4, 0x3c, 0x45, 0x57, 0x11, 0xaf}},
     "RIF"},

    // FvgqHMfL9yn39V79huDPy3YUNDoYJpuLWng2JfmQpump
    {{{0xdd, 0xc4, 0x70, 0x44, 0x57, 0xe3, 0x72, 0xc5, 0x87, 0x22, 0x56,
       0xa5, 0x44, 0xc5, 0xf1, 0xa2, 0x53, 0xd9, 0xc8, 0xdb, 0xc9, 0x41,
       0x01, 0xc8, 0xdd, 0x6e, 0x28, 0x5a, 0xb4, 0x1e, 0xe9, 0xbf}},
     "URO"},

    // 2zMMhcVQEXDtdE6vsFS7S7D5oUodfJHE8vd1gnBouauv
    {{{0x1d, 0x8c, 0xcf, 0x87, 0xac, 0x01, 0x47, 0xba, 0xe7, 0x56, 0xeb,
       0x96, 0x3a, 0x2e, 0xf6, 0x24, 0x4c, 0x96, 0x91, 0x56, 0x9a, 0x8e,
       0xc0, 0x8f, 0x00, 0x20, 0xa2, 0xeb, 0x8f, 0xbd, 0xb5, 0xa1}},
     "PENGU"},

    // 9BB6NFEcjBCtnNLFko2FqVQBq8HHM13kCyYcdQbgpump
    {{{0x79, 0x78, 0xb7, 0x14, 0x45, 0x3c, 0xd3, 0xe8, 0x7a, 0xeb, 0x1f,
       0xc0, 0x9b, 0xf0, 0x67, 0xf9, 0x6c, 0xd2, 0xd4, 0xd6, 0x9b, 0x57,
       0x13, 0x95, 0xaa, 0x9b, 0xf1, 0x86, 0xaf, 0xf9, 0xda, 0x3f}},
     "Fartcoin"},

    // BNso1VUJnh4zcfpZa6986Ea66P6TCp59hvtNJ8b1X85
    {{{0x02, 0xa8, 0x8b, 0x06, 0xfa, 0xb4, 0x0a, 0x8c, 0xd2, 0x93, 0xf0,
       0xc5, 0x27, 0x58, 0x7e, 0x62, 0xd2, 0xff, 0xab, 0x76, 0x6f, 0xca,
       0x08, 0xb7, 0xf6, 0xf3, 0xc9, 0x19, 0xee, 0x73, 0x1b, 0x12}},
     "BNSOL"},

    // jupSoLaHXQiZZTSfEWMTRRgpnyFm8f6sZdosWBjx93v
    {{{0x0a, 0xfe, 0x1d, 0x91, 0x67, 0x14, 0x22, 0xc7, 0x65, 0xc7, 0xa0,
       0x6a, 0x11, 0x39, 0xff, 0x61, 0x39, 0xd3, 0x80, 0xfc, 0xb4, 0x22,
       0xba, 0x78, 0xf7, 0x78, 0xbe, 0xd5, 0x3c, 0x69, 0x7d, 0x81}},
     "JupSOL"},

    // bioJ9JTqW62MLz7UKHU69gtKhPpGi1BQhccj2kmSvUJ
    {{{0x08, 0xe5, 0x02, 0x46, 0x2e, 0xb4, 0xcd, 0xb7, 0x35, 0xb8, 0x3a,
       0xcc, 0x7e, 0x9c, 0x54, 0xa3, 0x5e, 0x07, 0xad, 0x51, 0x85, 0x96,
       0xe5, 0xef, 0xe9, 0x63, 0xee, 0x88, 0x9c, 0xd1, 0x55, 0x6b}},
     "BIO"},

    // KENJSUYLASHUMfHyy5o4Hp2FdNqZg1AsUPhfH2kYvEP
    {{{0x04, 0xab, 0x91, 0xa7, 0xa9, 0x18, 0xf5, 0x78, 0xd8, 0x5e, 0x51,
       0xd0, 0x1b, 0xc9, 0xe4, 0xc2, 0x80, 0x15, 0x3e, 0x5f, 0x5c, 0x77,
       0xed, 0xf8, 0xe4, 0xb5, 0xeb, 0xb3, 0xd1, 0x0c, 0x10, 0xa4}},
     "GRIFFAIN"},

    // MEFNBXixkEbait3xn9bkm8WsJzXtVsaJEn4c8Sam21u
    {{{0x05, 0x2e, 0x98, 0x6a, 0x95, 0x5e, 0x14, 0x29, 0x68, 0xf2, 0x26,
       0xb6, 0xa1, 0x73, 0x45, 0xce, 0xa6, 0x0b, 0xfa, 0x3c, 0x8c, 0xd4,
       0x26, 0x0a, 0xfe, 0xdb, 0xcb, 0x2f, 0xba, 0x37, 0x14, 0x28}},
     "ME"},

    // 9McvH6w97oewLmPxqQEoHUAv3u5iYMyQ9AeZZhguYf1T
    {{{0x7c, 0x25, 0xb9, 0x90, 0x6b, 0x93, 0xa8, 0xaa, 0x9a, 0xc1, 0x7a,
       0x40, 0xfc, 0x11, 0x27, 0x0d, 0x94, 0x6a, 0xc8, 0xc1, 0x05, 0xcb,
       0x19, 0x64, 0xa8, 0x4b, 0x94, 0x68, 0x9f, 0xc6, 0x90, 0xea}},
     "Anon"},

    // DKu9kykSfbN5LBfFXtNNDPaX35o4Fv6vJ9FKk7pZpump
    {{{0xb7, 0x23, 0xaa, 0x3d, 0xf8, 0xe2, 0x2d, 0x34, 0x2a, 0xca, 0x68,
       0x24, 0x68, 0x1b, 0x63, 0xca, 0x76, 0x7c, 0x4b, 0x1f, 0x10, 0x15,
       0xd3, 0xce, 0x70, 0xed, 0xb8, 0x32, 0x7e, 0xb9, 0x1c, 0x2f}},
     "AVA"},

    // 63LfDmNb3MQ8mw9MtZ2To9bEA2M71kZUUGq5tiJxcqj9
    {{{0x4a, 0xe3, 0xd3, 0x20, 0x82, 0x05, 0x44, 0xff, 0xfa, 0x2e, 0x6d,
       0xae, 0x60, 0xf8, 0xed, 0x2b, 0xc3, 0x42, 0x6d, 0x8d, 0xe3, 0xd7,
       0xf7, 0x7d, 0xdf, 0x35, 0x0c, 0x18, 0xfd, 0x6b, 0x31, 0x94}},
     "GIGA"},

    // eL5fUxj2J4CiQsmW85k5FG9DvuQjjUoBHoQBi2Kpump
    {{{0x09, 0x90, 0x10, 0x70, 0x9d, 0x92, 0x7f, 0xec, 0xe1, 0x7c, 0x90,
       0x43, 0x05, 0x81, 0xaa, 0xd5, 0x06, 0x2a, 0x64, 0x06, 0xa5, 0x52,
       0xfe, 0x72, 0x9b, 0xf2, 0x42, 0x5c, 0x02, 0xc4, 0x3f, 0xcf}},
     "UFD"},

    // 6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN
    {{{0x56, 0x5b, 0x78, 0xba, 0xec, 0x5b, 0xd6, 0xff, 0x06, 0x63, 0x33,
       0x18, 0xea, 0x20, 0xe7, 0xf6, 0x39, 0x8d, 0x2f, 0x32, 0x80, 0xe8,
       0xf7, 0xf8, 0xc3, 0x80, 0x4e, 0x28, 0x8e, 0x78, 0xa7, 0x8d}},
     "TRUMP"},

    // FUAfBo2jgks6gB4Z4LfZkqSZgzNucisEHqnNebaRxM1P
    {{{0xd6, 0xf9, 0x38, 0x36, 0x67, 0x9c, 0xa3, 0x2a, 0xe3, 0xfb, 0x0d,
       0x47, 0x3b, 0x75, 0xfa, 0xdf, 0x4b, 0x1f, 0x6c, 0xe4, 0x0d, 0x3e,
       0x85, 0xf9, 0x16, 0xeb, 0x0b, 0x1d, 0xfa, 0xb9, 0x58, 0x9e}},
     "MELANIA"}};

const char* get_token_symbol(const Pubkey* mint_address) {
    for (size_t i = 0; i < ARRAY_LEN(TOKEN_REGISTRY); i++) {
        const TokenInfo* info = &TOKEN_REGISTRY[i];

        if (memcmp(&(info->mint_address), mint_address, PUBKEY_SIZE) == 0) {
            return info->symbol;
        }
    }
    return "???";
}
