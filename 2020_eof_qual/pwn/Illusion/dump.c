__int64 __fastcall sub_1(__int64 a1) {
    __int64 v1;            // rdx
    __int64 result;        // rax
    int j;                 // [rsp+Ch] [rbp-634h]
    int v4;                // [rsp+10h] [rbp-630h]
    int v5;                // [rsp+14h] [rbp-62Ch]
    int v6;                // [rsp+18h] [rbp-628h]
    int v7;                // [rsp+1Ch] [rbp-624h]
    int k;                 // [rsp+20h] [rbp-620h]
    int v9;                // [rsp+24h] [rbp-61Ch]
    int v10;               // [rsp+28h] [rbp-618h]
    int v11;               // [rsp+2Ch] [rbp-614h]
    int v12;               // [rsp+30h] [rbp-610h]
    int l;                 // [rsp+34h] [rbp-60Ch]
    int v14;               // [rsp+38h] [rbp-608h]
    int v15;               // [rsp+3Ch] [rbp-604h]
    int m;                 // [rsp+40h] [rbp-600h]
    int ii;                // [rsp+44h] [rbp-5FCh]
    int v18;               // [rsp+48h] [rbp-5F8h]
    int v19;               // [rsp+48h] [rbp-5F8h]
    int v20;               // [rsp+48h] [rbp-5F8h]
    int v21;               // [rsp+48h] [rbp-5F8h]
    int v22;               // [rsp+48h] [rbp-5F8h]
    int jj;                // [rsp+4Ch] [rbp-5F4h]
    int v24;               // [rsp+50h] [rbp-5F0h]
    int v25;               // [rsp+50h] [rbp-5F0h]
    int v26;               // [rsp+54h] [rbp-5ECh]
    int v27;               // [rsp+58h] [rbp-5E8h]
    int v28;               // [rsp+5Ch] [rbp-5E4h]
    int v29;               // [rsp+60h] [rbp-5E0h]
    int kk;                // [rsp+64h] [rbp-5DCh]
    int ll;                // [rsp+68h] [rbp-5D8h]
    int v32;               // [rsp+68h] [rbp-5D8h]
    int mm;                // [rsp+6Ch] [rbp-5D4h]
    int nn;                // [rsp+70h] [rbp-5D0h]
    int i1;                // [rsp+74h] [rbp-5CCh]
    int v36;               // [rsp+80h] [rbp-5C0h]
    int v37;               // [rsp+84h] [rbp-5BCh]
    int v38;               // [rsp+94h] [rbp-5ACh]
    int v39;               // [rsp+98h] [rbp-5A8h]
    int v40;               // [rsp+9Ch] [rbp-5A4h]
    __int64 i;             // [rsp+A0h] [rbp-5A0h]
    __int64 v42;           // [rsp+A0h] [rbp-5A0h]
    signed __int64 v43;    // [rsp+A0h] [rbp-5A0h]
    __int64 n;             // [rsp+A8h] [rbp-598h]
    __int64 v45;           // [rsp+B0h] [rbp-590h]
    unsigned __int64 v46;  // [rsp+B8h] [rbp-588h]
    __int64 v47;           // [rsp+C0h] [rbp-580h]
    __int64 v48;           // [rsp+C8h] [rbp-578h]
    __int64 v49;           // [rsp+D0h] [rbp-570h]
    __int64 v50;           // [rsp+D8h] [rbp-568h]
    __int64 v51;           // [rsp+F0h] [rbp-550h]
    __int64 v52;           // [rsp+100h] [rbp-540h]
    int *v53;              // [rsp+108h] [rbp-538h]
    int *v54;              // [rsp+110h] [rbp-530h]
    int v55[64];           // [rsp+130h] [rbp-510h]
    int v56[64];           // [rsp+230h] [rbp-410h]
    char v57[6];           // [rsp+330h] [rbp-310h] BYREF
    char v58[5];           // [rsp+336h] [rbp-30Ah] BYREF
    char v59[8];           // [rsp+33Bh] [rbp-305h] BYREF
    char v60[56];          // [rsp+430h] [rbp-210h] BYREF
    int v61;               // [rsp+468h] [rbp-1D8h] BYREF
    unsigned __int64 v62;  // [rsp+638h] [rbp-8h]

    v62 = __readfsqword(0x28u);
    qmemcpy(v57, "/proc", 5);
    v57[5] = v57[0];
    v58[4] = v57[0];
    qmemcpy(v58, "self", 4);
    strcpy(v59, "exe");
    __asm { syscall; Low latency system call }
    // i == rbp-0x5a0
    // 47 == 0x2f == ord('/')
    // v60 == rbp-0x210 == "/home/u1f383/u1f383_ctf.log/2020_eof_qual/pwn/Illusion/illusion"
    for (i = 89; v60[i] != 47; --i);
    // 不知道為啥是 89，反正會拿到 ptr 'illusion'
    v60[i + 2] = 108; // 0x6c
    v60[i + 4] = 103; // 0x67
    v60[i + 3] = 97; // 0x61
    v60[i + 1] = 102; // 0x66
    // flag
    v60[i + 5] = 0;
    __asm { syscall; Low latency system call }
    // open('/home/u1f383/u1f383_ctf.log/2020_eof_qual/pwn/Illusion/flag')
    // fd in rbp-0x560

    for (j = 0; j <= 511; ++j) // 4 md5 (128*4)
        v60[j] = 0;
    __asm
    {
    // read flag into rbp-0x210] == v60
    syscall; Low latency system call
    // close flag
    syscall; Low latency system call
    }

    v4 = 0x67452301;
    v5 = 0xEFCDAB89;
    v6 = 0x98BADCFE;
    v7 = 0x10325476;
    v55[0] = 7;
    v55[1] = 12;
    v55[2] = 17;
    v55[3] = 22;

    v55[4] = 7;
    v55[5] = 12;
    v55[6] = 17;
    v55[7] = 22;

    v55[8] = 7;
    v55[9] = 12;
    v55[10] = 17;
    v55[11] = 22;

    v55[12] = 7;
    v55[13] = 12;
    v55[14] = 17;
    v55[15] = 22;

    v55[16] = 5;
    v55[17] = 9;
    v55[18] = 14;
    v55[19] = 20;

    v55[20] = 5;
    v55[21] = 9;
    v55[22] = 14;
    v55[23] = 20;

    v55[24] = 5;
    v55[25] = 9;
    v55[26] = 14;
    v55[27] = 20;

    v55[28] = 5;
    v55[29] = 9;
    v55[30] = 14;
    v55[31] = 20;

    v55[32] = 4;
    v55[33] = 11;
    v55[34] = 16;
    v55[35] = 23;

    v55[36] = 4;
    v55[37] = 11;
    v55[38] = 16;
    v55[39] = 23;

    v55[40] = 4;
    v55[41] = 11;
    v55[42] = 16;
    v55[43] = 23;

    v55[44] = 4;
    v55[45] = 11;
    v55[46] = 16;
    v55[47] = 23;

    v55[48] = 6;
    v55[49] = 10;
    v55[50] = 15;
    v55[51] = 21;

    v55[52] = 6;
    v55[53] = 10;
    v55[54] = 15;
    v55[55] = 21;

    v55[56] = 6;
    v55[57] = 10;
    v55[58] = 15;
    v55[59] = 21;

    v55[60] = 6;
    v55[61] = 10;
    v55[62] = 15;
    v55[63] = 21;

    v56[0] = -680876936;
    v56[1] = -389564586;
    v56[2] = 606105819;
    v56[3] = -1044525330;
    v56[4] = -176418897;
    v56[5] = 1200080426;
    v56[6] = -1473231341;
    v56[7] = -45705983;
    v56[8] = 1770035416;
    v56[9] = -1958414417;
    v56[10] = -42063;
    v56[11] = -1990404162;
    v56[12] = 1804603682;
    v56[13] = -40341101;
    v56[14] = -1502002290;
    v56[15] = 1236535329;
    v56[16] = -165796510;
    v56[17] = -1069501632;
    v56[18] = 643717713;
    v56[19] = -373897302;
    v56[20] = -701558691;
    v56[21] = 38016083;
    v56[22] = -660478335;
    v56[23] = -405537848;
    v56[24] = 568446438;
    v56[25] = -1019803690;
    v56[26] = -187363961;
    v56[27] = 1163531501;
    v56[28] = -1444681467;
    v56[29] = -51403784;
    v56[30] = 1735328473;
    v56[31] = -1926607734;
    v56[32] = -378558;
    v56[33] = -2022574463;
    v56[34] = 1839030562;
    v56[35] = -35309556;
    v56[36] = -1530992060;
    v56[37] = 1272893353;
    v56[38] = -155497632;
    v56[39] = -1094730640;
    v56[40] = 681279174;
    v56[41] = -358537222;
    v56[42] = -722521979;
    v56[43] = 76029189;
    v56[44] = -640364487;
    v56[45] = -421815835;
    v56[46] = 530742520;
    v56[47] = -995338651;
    v56[48] = -198630844;
    v56[49] = 1126891415;
    v56[50] = -1416354905;
    v56[51] = -57434055;
    v56[52] = 1700485571;
    v56[53] = -1894986606;
    v56[54] = -1051523;
    v56[55] = -2054922799;
    v56[56] = 1873313359;
    v56[57] = -30611744;
    v56[58] = -1560198380;
    v56[59] = 1309151649;
    v56[60] = -145523070;
    v56[61] = -1120210379;
    v56[62] = 718787259;
    v56[63] = -343485551;


    v60[0] = 0x80; // mov 0x80 in flag end
    v1 = (__int64)&v61;
    v61 = 0;
    // 好累 = =，0x555555555a6d




    for (k = 0; k < 56; k += 64) {
        v1 = (__int64)v60;
        v9 = v4;
        v10 = v5;
        v11 = v6;
        v12 = v7;
        for (l = 0; l <= 63; ++l) {
            if (l > 15) {
                if (l > 31) {
                    if (l > 47) {
                        v14 = v11 ^ (v10 | ~v12);
                        v15 = 7 * l % 16;
                    } else {
                        v14 = v12 ^ v11 ^ v10;
                        v15 = (3 * l + 5) % 16;
                    }
                } else {
                    v14 = v10 & v12 | v11 & ~v12;
                    v15 = (5 * l + 1) % 16;
                }
            } else {
                v14 = v11 & v10 | v12 & ~v10;
                v15 = l;
            }
            v40 = v12;
            v12 = v11;
            v11 = v10;
            a1 = (unsigned int)v55[l];
            v1 = (unsigned int)__ROL4__(*(_DWORD *)&v60[4 * v15 + k] + v56[l] + v14 + v9, a1);
            v10 += v1;
            v9 = v40;
        }
        v4 += v9;
        v5 += v10;
        v6 += v11;
        v7 += v12;
    }
    fc84b086
    0542b8f0
    963dbabc
    5e66d0b7
    // md5(b'FLAG{QQW').hexdigest() == 03fd64b185ebb68bef9e4cd5bc5e5de7
    // md5(b'WOWQQ}\n').hexdigest() == b6ac271f18a9e4798ee0c0fb5559b4c0
    for (m = 0; m <= 511; ++m)
        v60[m] = 0;
    // clear

    
    if (v4 == -58412922 && v5 == 0x542b8f0 && v6 == -1774339396 && v7 == 0x5e66d0b7) {
        for (n = -4096; *(_DWORD *)n != 1179403647; n -= 4096)
            ;
        v36 = *(unsigned __int16 *)(n + 54);
        v37 = *(unsigned __int16 *)(n + 56);
        v1 = *(_QWORD *)(n + 32);
        v51 = v1 + n;
        v45 = 0;
        v46 = 0;
        for (ii = 0; ii < v37; ++ii) {
            v1 = ii * v36;
            if (*(_DWORD *)(v1 + v51) == 2) {
                v45 = *(_QWORD *)(ii * v36 + v51 + 16) + n;
                v1 = ii * v36;
                v46 = *(_QWORD *)(v1 + v51 + 40);
                break;
            }
        }
        if (v45) {
            v47 = 0;
            v48 = 0;
            v49 = 0;
            v18 = 0;
            for (jj = 0; v46 > jj; jj += 16) {
                v1 = jj;
                v52 = *(_QWORD *)(jj + v45);
                switch (v52) {
                    case 23:
                        v1 = jj;
                        v47 = *(_QWORD *)(jj + v45 + 8);
                        ++v18;
                        break;
                    case 6:
                        v1 = jj;
                        v48 = *(_QWORD *)(jj + v45 + 8);
                        ++v18;
                        break;
                    case 5:
                        v1 = jj;
                        v49 = *(_QWORD *)(jj + v45 + 8);
                        ++v18;
                        break;
                }
                if (v18 == 3)
                    break;
                v1 = 16;
            }
            if (v18 == 3) {
                v24 = 0;
                v26 = 0;
                v27 = 0;
                v19 = 0;
                while (1) {
                    if (*(_BYTE *)(v24 + v49) == 112) {
                        if (*(_DWORD *)(++v24 + v49) == 1953393010 && (v24 += 4, *(_WORD *)(v24 + v49) == 102)) {
                            v26 = v24 - 5;
                            ++v19;
                        } else if (*(_DWORD *)(v24 + v49) == 7566453) {
                            v27 = v24 - 1;
                            ++v19;
                        }
                        if (v19 == 2)
                            break;
                    }
                    while (*(_BYTE *)(v24 + v49))
                        ++v24;
                    ++v24;
                }
                v25 = 0;
                v20 = 0;
                while (1) {
                    v38 = *(_DWORD *)((unsigned int)(24 * *(_DWORD *)(24 * v25 + v47 + 12)) + v48);
                    if (v38 == v26) {
                        v28 = v25;
                        ++v20;
                    } else if (v38 == v27) {
                        v29 = v25;
                        ++v20;
                    }
                    if (v20 == 2)
                        break;
                    ++v25;
                }
                v53 = (int *)(24 * v28 + v47 + 12);
                v54 = (int *)(24 * v29 + v47 + 12);
                v42 = 4096;
                __asm { syscall; Low latency system call }
                v39 = *v53;
                *v53 = *v54;
                *v54 = v39;
                v1 = 1;
                __asm { syscall; Low latency system call }
                v21 = 0;
                for (kk = 0; kk < v37; ++kk) {
                    v1 = kk * v36;
                    if (*(_DWORD *)(v1 + v51) == 1) {
                        v1 = kk * v36;
                        if (*(_DWORD *)(v1 + v51 + 4) == 4) {
                            v42 = *(_QWORD *)(kk * v36 + v51 + 40);
                            v1 = *(_QWORD *)(kk * v36 + v51 + 16);
                            v50 = v1 + n;
                            for (ll = 0; v42 > ll; ll = v32 + 1) {
                                do {
                                    v1 = ll;
                                    if (*(_BYTE *)(ll + v50) == 72)
                                        break;
                                    ++ll;
                                } while (v42 > ll);
                                if (v42 <= ll)
                                    break;
                                v32 = ll + 1;
                                v1 = 0x6877202C6F6C6C65;
                                if (*(_QWORD *)(v32 + v50) == 0x6877202C6F6C6C65) {
                                    v32 += 8;
                                    v1 = 0x6F79207369207461;
                                    if (*(_QWORD *)(v32 + v50) == 0x6F79207369207461) {
                                        v32 += 8;
                                        v1 = 0x3F656D616E207275;
                                        if (*(_QWORD *)(v32 + v50) == 0x3F656D616E207275) {
                                            v32 += 8;
                                            v1 = v32;
                                            if (*(_WORD *)(v32 + v50) == 10) {
                                                v21 = 1;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            if (v21 == 1)
                                break;
                        }
                    }
                }
                if (v21) {
                    v43 = (v42 + 4095) & 0xFFFFFFFFFFFFF000u;
                    __asm { syscall; Low latency system call }
                    v22 = 0;
                    for (mm = 0; v43 > mm; ++mm) {
                        switch (*(_BYTE *)(mm + v50)) {
                            case 'H':
                                if (*(_QWORD *)(++mm + v50) == 0x6877202C6F6C6C65) {
                                    mm += 8;
                                    if (*(_QWORD *)(mm + v50) == 0x6F79207369207461) {
                                        mm += 8;
                                        if (*(_QWORD *)(mm + v50) == 0x3F656D616E207275) {
                                            mm += 8;
                                            if (*(_WORD *)(mm + v50) == 10) {
                                                *(_BYTE *)(mm++ + v50) = 0;
                                                v22 |= 1u;
                                            }
                                        }
                                    }
                                }
                                break;
                            case 'N':
                                if (*(_QWORD *)(++mm + v50) == 0x6D206F7420656369) {
                                    mm += 8;
                                    if (*(_QWORD *)(mm + v50) == 0xA756F7920746565) {
                                        mm += 8;
                                        if (!*(_BYTE *)(mm + v50)) {
                                            *(_BYTE *)(mm - 1 + v50) = 0;
                                            v22 |= 2u;
                                        }
                                    }
                                }
                                break;
                            case 'A':
                                if (*(_QWORD *)(++mm + v50) == 0x20676E696874796E) {
                                    mm += 8;
                                    if (*(_QWORD *)(mm + v50) == 0x746E617720756F79) {
                                        mm += 8;
                                        if (*(_QWORD *)(mm + v50) == 0x20796173206F7420) {
                                            mm += 8;
                                            if (*(_QWORD *)(mm + v50) == 0xA3F7375206F74) {
                                                for (nn = 6; nn >= -24; --nn) {
                                                    a1 = mm + nn;
                                                    *(_BYTE *)(a1 + v50) = *(_BYTE *)(a1 - 1 + v50);
                                                }
                                                *(_BYTE *)(mm - 25 + v50) = 10;
                                                mm += 7;
                                                v22 |= 4u;
                                            }
                                        }
                                    }
                                }
                                break;
                            case 'W':
                                if (*(_QWORD *)(++mm + v50) == 0x7665696365722065) {
                                    mm += 8;
                                    if (*(_QWORD *)(mm + v50) == 0x2072756F79206465) {
                                        mm += 8;
                                        if (*(_QWORD *)(mm + v50) == 0xA6567617373656D) {
                                            mm += 8;
                                            if (!*(_BYTE *)(mm + v50)) {
                                                *(_BYTE *)(mm - 1 + v50) = 0;
                                                v22 |= 8u;
                                            }
                                        }
                                    }
                                }
                                break;
                            default:
                                if (*(_BYTE *)(mm + v50) == 71 && *(_QWORD *)(++mm + v50) == 0xA657962646F6F) {
                                    for (i1 = 6; i1 >= 0; --i1) {
                                        a1 = mm + i1;
                                        *(_BYTE *)(a1 + v50) = *(_BYTE *)(a1 - 1 + v50);
                                    }
                                    *(_BYTE *)(mm - 1 + v50) = 10;
                                    mm += 7;
                                    v22 |= 0x10u;
                                }
                                break;
                        }
                        if (v22 == 31)
                            break;
                    }
                    v1 = 1;
                    __asm { syscall; Low latency system call }
                }
            }
        }
    }
    result = v62 - __readfsqword(0x28u);
    if (result)
        result = MEMORY[0xFFFFFFFFFFFFFD77](a1, v1);
    return result;
}
