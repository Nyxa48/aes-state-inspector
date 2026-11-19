(function (root) {
  "use strict";

  // AES-128 temel sabitleri, FIPS-197 polinomsal katsayılar ve hazır test vektörleri
  const CONSTANTS = {
    ROUNDS: 10,                // 128-bit anahtar için toplam şifreleme tur sayısı
    WORDS: 44,                 // 11 tur × 4 sütun = 44 adet 32-bit anahtar kelimesi (W[0]..W[43])
    POLY_LOW: 0x1b,            // İndirgenemez polinom x^8 + x^4 + x^3 + x + 1 (0x11B) alt 8 biti
    AFFINE_CONST: 0x63,        // S-Box afin dönüşüm sabiti (sabit nokta olmamasını sağlar)
    INV_AFFINE_CONST: 0x05,    // InvS-Box ters afin dönüşüm sabiti
    AFFINE_SHIFTS: [1, 2, 3, 4],
    INV_AFFINE_SHIFTS: [1, 3, 6],
    DEFAULTS: {
      pt1: "ARABA",
      pt2: "ARABB",
      key: "2B7E151628AED2A6ABF7158809CF4F3C",
      pad: "zero"
    },
    PRESETS: {
      classroom: { pt1: "ARABA", pt2: "ARABB", key: "2B7E151628AED2A6ABF7158809CF4F3C", pad: "zero" },
      fips197: { pt1: "3243F6A8885A308D313198A2E0370734", pt2: "3243F6A8885A308D313198A2E0370735", key: "2B7E151628AED2A6ABF7158809CF4F3C", pad: "pkcs7" },
      zeros: { pt1: "00000000000000000000000000000000", pt2: "00000000000000000000000000000001", key: "00000000000000000000000000000000", pad: "zero" },
      ascii16: { pt1: "KRIPTOLOJI_DERSI", pt2: "KRIPTOLOJI_DERSJ", key: "000102030405060708090A0B0C0D0E0F", pad: "zero" }
    },
    MIX_MATRIX: [
      [0x02, 0x03, 0x01, 0x01],
      [0x01, 0x02, 0x03, 0x01],
      [0x01, 0x01, 0x02, 0x03],
      [0x03, 0x01, 0x01, 0x02]
    ],
    INV_MIX_MATRIX: [
      [0x0e, 0x0b, 0x0d, 0x09],
      [0x09, 0x0e, 0x0b, 0x0d],
      [0x0d, 0x09, 0x0e, 0x0b],
      [0x0b, 0x0d, 0x09, 0x0e]
    ]
  };

  const Format = {
    hex2: (b) => b.toString(16).toUpperCase().padStart(2, "0"),
    bin8: (b) => b.toString(2).padStart(8, "0"),
    hexStr: (arr) => arr.map((b) => Format.hex2(b)).join(" "),
    isPrintableAscii: (b) => b >= 32 && b <= 126
  };

  // 16 baytlık doğrusal diziyi 4x4 durum matrisine sütun-öncelikli (column-major) eşler
  const Layout = {
    coord: (idx) => ({ r: idx % 4, c: Math.floor(idx / 4), idx }),
    idx: (r, c) => c * 4 + r,
    // ShiftRows şifrelemede sola (c+r), deşifrelemede sağa (c-r+4) kaydırır
    shiftSourceCol: (c, r, isEnc) => (isEnc ? (c + r) % 4 : (c - r + 4) % 4)
  };

  // GF(2^8) sonlu cisim aritmetiği (mod 0x11B)
  const GF = {
    rotLeft8(b, k) {
      return ((b << k) | (b >>> (8 - k))) & 0xff;
    },
    // xtime: Sayıyı 1 bit sola kaydırır; MSB=1 taşması varsa 0x1B ile XOR alır
    xtime(a) {
      return ((a << 1) ^ ((a & 0x80) ? CONSTANTS.POLY_LOW : 0x00)) & 0xff;
    },
    // İki baytın GF(2^8) polinomsal çarpımı (bit bazlı xtime toplamı)
    mul(a, b) {
      let res = 0;
      let cur = a & 0xff;
      for (let i = 0; i < 8; i++) {
        if ((b >> i) & 1) res ^= cur;
        cur = GF.xtime(cur);
      }
      return res & 0xff;
    },
    inv(a) {
      // By FIPS-197 convention, 0x00 maps to 0x00 because it has no multiplicative inverse.
      if (a === 0) return 0;
      for (let x = 1; x < 256; x++) {
        if (GF.mul(a, x) === 1) return x;
      }
      throw new Error(`No GF(2^8) inverse found for ${a}`);
    },
    affineForward(b) {
      let out = b;
      for (const shift of CONSTANTS.AFFINE_SHIFTS) out ^= GF.rotLeft8(b, shift);
      return (out ^ CONSTANTS.AFFINE_CONST) & 0xff;
    },
    affineInverse(b) {
      let out = CONSTANTS.INV_AFFINE_CONST;
      for (const shift of CONSTANTS.INV_AFFINE_SHIFTS) out ^= GF.rotLeft8(b, shift);
      return out & 0xff;
    },
    describeAffine(inB, outB, isEnc) {
      if (isEnc) {
        const inv = GF.inv(inB);
        return {
          isEnc: true,
          inB,
          inv,
          invCheckProd: GF.mul(inB, inv),
          outB,
          rotations: CONSTANTS.AFFINE_SHIFTS.map((s) => ({ shift: s, val: GF.rotLeft8(inv, s) })),
          constant: CONSTANTS.AFFINE_CONST
        };
      }
      const postAff = GF.affineInverse(inB);
      return {
        isEnc: false,
        inB,
        postAff,
        outB,
        rotations: CONSTANTS.INV_AFFINE_SHIFTS.map((s) => ({ shift: s, val: GF.rotLeft8(inB, s) })),
        constant: CONSTANTS.INV_AFFINE_CONST
      };
    },
    describeMulStep(k, b) {
      const product = GF.mul(k, b);
      return {
        k,
        b,
        product,
        overflow: (b & 0x80) !== 0,
        shifted: (b << 1) & 0xff,
        x2: GF.mul(0x02, b)
      };
    }
  };

  // 256 elemanlı S-Box, InvS-Box ve tur sabiti (Rcon) tablolarını açılışta cebirsel olarak üretir
  const TABLES = (() => {
    const sbox = new Uint8Array(256);
    const invSbox = new Uint8Array(256);
    // Rcon[1..10]: 0x01'in GF(2^8) üzerinde her turda xtime ile 2 katı alınarak üretilir (9. turda 0x80 -> 0x1B taşar)
    const rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    for (let i = 0; i < 256; i++) {
      const val = GF.affineForward(GF.inv(i)); // Önce GF(2^8) çarpımsal tersi, sonra afin dönüşüm
      sbox[i] = val;
      invSbox[val] = i;                        // Ters S-Box birebir ters eşleme ile doldurulur
    }
    return { sbox, invSbox, rcon };
  })();

  // Düz metin girdisini (32 hex veya ASCII) 16 baytlık bloğa dönüştürür; eksikse Zero veya PKCS#7 ile doldurur
  function analyzeBlockInput(raw, padMode) {
    const trimmed = String(raw ?? "").trim();
    if (/^[0-9a-fA-F]{32}$/.test(trimmed)) {
      const bytes = [];
      for (let i = 0; i < 32; i += 2) bytes.push(parseInt(trimmed.slice(i, i + 2), 16));
      return { bytes, trimmed, mode: "hex", charLen: trimmed.length, isTruncated: false };
    }
    const bytes = [];
    const cap = Math.min(trimmed.length, 16);
    for (let i = 0; i < cap; i++) bytes.push(trimmed.charCodeAt(i) & 0xff);
    // PKCS#7 eksik bayt sayısı kadar aynı değeri yazar (örn. 11 eksikse 0x0B); Zero 0x00 doldurur
    const padVal = padMode === "pkcs7" ? (16 - bytes.length) : 0x00;
    while (bytes.length < 16) bytes.push(padVal);
    return { bytes, trimmed, mode: "ascii", charLen: trimmed.length, isTruncated: trimmed.length > 16 };
  }

  // 128-bit anahtar girdisini temizler; 32 hex'ten kısaysa sonunu 00 ile 16 bayta tamamlar
  function analyzeKeyInput(raw) {
    const trimmed = String(raw ?? "").trim();
    const cleanHex = trimmed.replace(/[^0-9a-fA-F]/g, "");
    const noWs = trimmed.replace(/\s+/g, "");
    const normalized = cleanHex.padEnd(32, "0").slice(0, 32);
    const bytes = [];
    for (let i = 0; i < 32; i += 2) bytes.push(parseInt(normalized.slice(i, i + 2), 16));
    return {
      bytes,
      cleanHex,
      hexCount: cleanHex.length,
      hasInvalidChars: noWs !== cleanHex,
      isShort: cleanHex.length < 32
    };
  }

  // İki 16 baytlık blok arasındaki farklı bayt ve farklı bit (Hamming mesafesi) sayısını hesaplar
  function countBitDiff(a, b) {
    let bits = 0;
    let bytes = 0;
    for (let i = 0; i < a.length; i++) {
      let x = a[i] ^ b[i];
      if (x !== 0) bytes++;
      while (x) {
        bits += x & 1;
        x >>>= 1;
      }
    }
    return { bits, bytes };
  }

  function getRoundSteps(roundIdx, isEnc) {
    if (roundIdx === 0) return ["input", "rk", "afterKey"];
    if (isEnc) {
      return roundIdx < CONSTANTS.ROUNDS
        ? ["input", "afterSub", "afterShift", "afterMix", "afterKey"]
        : ["input", "afterSub", "afterShift", "afterKey"];
    }
    return roundIdx < CONSTANTS.ROUNDS
      ? ["input", "afterShift", "afterSub", "afterKey", "afterMix"]
      : ["input", "afterShift", "afterSub", "afterKey"];
  }

  function normalizeStepKey(roundIdx, stepKey, isEnc) {
    const valid = getRoundSteps(roundIdx, isEnc);
    if (valid.includes(stepKey)) return stepKey;
    return roundIdx === 0 ? "afterKey" : "afterSub";
  }

  // AES-128 çekirdek motoru: anahtar genişletme, 4 tur dönüşümü, şifreleme ve deşifreleme
  const AES = {
    // 16 baytlık anahtardan 44 kelime (11 tur anahtarı) üretir
    expandKey(key) {
      const W = [];
      const logs = [];
      for (let i = 0; i < 4; i++) {
        W[i] = key.slice(i * 4, i * 4 + 4);
        logs[i] = { type: "init", i, word: W[i].slice() };
      }
      for (let i = 4; i < CONSTANTS.WORDS; i++) {
        const prev = W[i - 1].slice();
        const prev4 = W[i - 4].slice();
        if (i % 4 === 0) {
          // 4'ün katı indekslerde RotWord -> SubWord -> Rcon XOR -> W[i-4] XOR uygulanır
          const rot = [prev[1], prev[2], prev[3], prev[0]];
          const sub = rot.map((b) => TABLES.sbox[b]);
          const rc = TABLES.rcon[i / 4];
          const rconXor = [sub[0] ^ rc, sub[1], sub[2], sub[3]];
          W[i] = prev4.map((b, idx) => b ^ rconXor[idx]);
          logs[i] = { type: "rot", i, prev, prev4, rot, sub, rc, rconXor, word: W[i].slice() };
        } else {
          // Diğer kelimelerde doğrudan W[i-4] XOR W[i-1] yapılır
          W[i] = prev4.map((b, idx) => b ^ prev[idx]);
          logs[i] = { type: "xor", i, prev, prev4, word: W[i].slice() };
        }
      }
      const roundKeys = [];
      for (let r = 0; r <= CONSTANTS.ROUNDS; r++) {
        const rk = [];
        for (let c = 0; c < 4; c++) rk.push(...W[r * 4 + c]);
        roundKeys.push(rk);
      }
      return { W, logs, roundKeys };
    },

    // 1. SubBytes / InvSubBytes: Her baytı doğrusal olmayan S-Box (veya InvS-Box) değeriyle değiştirir
    subBytes(s, inv = false) {
      const box = inv ? TABLES.invSbox : TABLES.sbox;
      return s.map((b) => box[b]);
    },

    // 2. ShiftRows / InvShiftRows: r. satırı r birim sola (deşifrelemede sağa) döndürerek sütunları karıştırır
    shiftRows(s, inv = false) {
      const out = new Array(16);
      for (let r = 0; r < 4; r++) {
        for (let c = 0; c < 4; c++) {
          const srcCol = Layout.shiftSourceCol(c, r, !inv);
          out[Layout.idx(r, c)] = s[Layout.idx(r, srcCol)];
        }
      }
      return out;
    },

    // 3. MixColumns / InvMixColumns: Her 4 baytlık sütunu GF(2^8) MDS matrisiyle çarparak yayılma (diffusion) sağlar
    mixColumns(s, inv = false) {
      const M = inv ? CONSTANTS.INV_MIX_MATRIX : CONSTANTS.MIX_MATRIX;
      const out = new Array(16);
      for (let c = 0; c < 4; c++) {
        for (let r = 0; r < 4; r++) {
          out[Layout.idx(r, c)] =
            GF.mul(M[r][0], s[c * 4]) ^
            GF.mul(M[r][1], s[c * 4 + 1]) ^
            GF.mul(M[r][2], s[c * 4 + 2]) ^
            GF.mul(M[r][3], s[c * 4 + 3]);
        }
      }
      return out;
    },

    // 4. AddRoundKey: Durum matrisini ilgili 16 baytlık tur anahtarıyla bit bazında XOR'lar
    addRoundKey(s, rk) {
      return s.map((b, i) => b ^ rk[i]);
    },

    // Tur 0 AddRoundKey ile başlar; Tur 1..9 tam 4 adım, Tur 10 MixColumns olmadan biter
    encrypt(pt, rks) {
      let state = AES.addRoundKey(pt, rks[0]);
      const rounds = [{
        round: 0,
        input: pt.slice(),
        rk: rks[0].slice(),
        afterKey: state.slice()
      }];
      for (let r = 1; r <= CONSTANTS.ROUNDS; r++) {
        const input = state.slice();
        const afterSub = AES.subBytes(input, false);
        const afterShift = AES.shiftRows(afterSub, false);
        const afterMix = r < CONSTANTS.ROUNDS ? AES.mixColumns(afterShift, false) : null;
        const afterKey = AES.addRoundKey(afterMix || afterShift, rks[r]);
        state = afterKey;
        rounds.push({ round: r, input, afterSub, afterShift, afterMix, rk: rks[r].slice(), afterKey });
      }
      return rounds;
    },

    // Deşifreleme Tur 10 anahtarıyla başlar; InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns sırasıyla iner
    decrypt(ct, rks) {
      let state = AES.addRoundKey(ct, rks[CONSTANTS.ROUNDS]);
      const rounds = [{
        round: CONSTANTS.ROUNDS,
        input: ct.slice(),
        rk: rks[CONSTANTS.ROUNDS].slice(),
        afterKey: state.slice()
      }];
      for (let r = CONSTANTS.ROUNDS - 1; r >= 0; r--) {
        const input = state.slice();
        const afterShift = AES.shiftRows(input, true);
        const afterSub = AES.subBytes(afterShift, true);
        const afterKey = AES.addRoundKey(afterSub, rks[r]);
        const afterMix = r > 0 ? AES.mixColumns(afterKey, true) : null;
        state = afterMix || afterKey;
        rounds.push({ round: r, input, afterShift, afterSub, rk: rks[r].slice(), afterKey, afterMix });
      }
      return rounds;
    }
  };

  function computeDependencies(step, idx, roundIdx, isEnc) {
    const { r, c } = Layout.coord(idx);
    const dep = {
      sourceStep: null,
      sourceIndices: new Set(),
      keyStep: null,
      keyIndices: new Set(),
      rowBandStep: null,
      rowBandRow: -1
    };
    const steps = getRoundSteps(roundIdx, isEnc);
    const pos = steps.indexOf(step);

    if (roundIdx === 0) {
      if (step === "afterKey") {
        dep.sourceStep = "input";
        dep.sourceIndices.add(idx);
        dep.keyStep = "rk";
        dep.keyIndices.add(idx);
      } else if (step === "rk") {
        dep.sourceStep = "input";
        dep.sourceIndices.add(idx);
        dep.keyStep = "afterKey";
        dep.keyIndices.add(idx);
      } else {
        dep.keyStep = "afterKey";
        dep.keyIndices.add(idx);
      }
      return dep;
    }

    if (step === "input") {
      dep.keyStep = steps[1];
      dep.keyIndices.add(idx);
      return dep;
    }

    const prevStep = pos > 0 ? steps[pos - 1] : null;
    if (step === "afterShift") {
      const srcCol = Layout.shiftSourceCol(c, r, isEnc);
      dep.sourceStep = prevStep;
      dep.sourceIndices.add(Layout.idx(r, srcCol));
      dep.rowBandStep = prevStep;
      dep.rowBandRow = r;
    } else if (step === "afterMix") {
      dep.sourceStep = prevStep;
      for (let row = 0; row < 4; row++) dep.sourceIndices.add(Layout.idx(row, c));
    } else {
      dep.sourceStep = prevStep;
      dep.sourceIndices.add(idx);
    }
    return dep;
  }

  function computeCellTrace({ rData, step, idx, roundIdx, isEnc, keyData }) {
    const coord = Layout.coord(idx);
    const safeStep = normalizeStepKey(roundIdx, step, isEnc);
    const dep = computeDependencies(safeStep, idx, roundIdx, isEnc);

    if (safeStep === "input") {
      return {
        coord,
        step: safeStep,
        dep,
        detail: { kind: "input", val: rData.input[idx], nextStep: dep.keyStep, roundIdx, round: rData.round, hasMix: Boolean(rData.afterMix) }
      };
    }

    if (safeStep === "afterSub") {
      const inB = isEnc ? rData.input[idx] : rData.afterShift[idx];
      const outB = rData.afterSub[idx];
      return {
        coord,
        step: safeStep,
        dep,
        detail: {
          kind: "afterSub",
          inB,
          inv: GF.inv(inB),
          outB,
          boxName: isEnc ? "S-Box" : "InvS-Box",
          affine: GF.describeAffine(inB, outB, isEnc),
          sboxHl: { byte: inB, inv: !isEnc }
        }
      };
    }

    if (safeStep === "afterShift") {
      const srcCol = Layout.shiftSourceCol(coord.c, coord.r, isEnc);
      const srcArr = isEnc ? rData.afterSub : rData.input;
      return {
        coord,
        step: safeStep,
        dep,
        detail: {
          kind: "afterShift",
          srcCol,
          val: rData.afterShift[idx],
          beforeRow: [0, 1, 2, 3].map((col) => ({ col, val: srcArr[Layout.idx(coord.r, col)] })),
          afterRow: [0, 1, 2, 3].map((col) => ({ col, val: rData.afterShift[Layout.idx(coord.r, col)] }))
        }
      };
    }

    if (safeStep === "afterMix") {
      const src = isEnc ? rData.afterShift : rData.afterKey;
      const colBytes = src.slice(coord.c * 4, coord.c * 4 + 4);
      const M = isEnc ? CONSTANTS.MIX_MATRIX : CONSTANTS.INV_MIX_MATRIX;
      const coeffs = M[coord.r];
      return {
        coord,
        step: safeStep,
        dep,
        detail: {
          kind: "afterMix",
          colBytes,
          coeffs,
          terms: [0, 1, 2, 3].map((i) => GF.describeMulStep(coeffs[i], colBytes[i])),
          outVal: rData.afterMix[idx]
        }
      };
    }

    const pre = roundIdx === 0 ? rData.input : (isEnc ? (rData.afterMix || rData.afterShift) : rData.afterSub);
    const wi = rData.round * 4 + coord.c;
    return {
      coord,
      step: safeStep,
      dep,
      detail: {
        kind: safeStep === "rk" ? "rk" : "afterKey",
        a: pre[idx],
        k: rData.rk[idx],
        res: rData.afterKey[idx],
        wi,
        wordBytes: keyData.W[wi],
        round: rData.round
      }
    };
  }

  // Bloktaki tek bir baytın belirtilen bitini ters çevirip 32 karakterlik hex string döndürür (+1 bit çığ etkisi testi)
  function flipSingleBitHex(rawStr, padMode, byteIndex = 0, bitMask = 0x01) {
    const bytes = analyzeBlockInput(rawStr, padMode).bytes.slice();
    const safeIdx = ((byteIndex % 16) + 16) % 16;
    bytes[safeIdx] = (bytes[safeIdx] ^ bitMask) & 0xff;
    return bytes.map((b) => Format.hex2(b)).join("");
  }

  // İki düz metni aynı anahtarla şifreleyip Tur 0..10 arasındaki bayt ve bit farklarını (çığ etkisini) hesaplar
  function computeAvalanche(pt1Raw, pt2Raw, keyRaw, padMode) {
    const pt1Info = analyzeBlockInput(pt1Raw, padMode);
    const pt2Info = analyzeBlockInput(pt2Raw, padMode);
    const keyInfo = analyzeKeyInput(keyRaw);
    const keyData = AES.expandKey(keyInfo.bytes);
    const enc1 = AES.encrypt(pt1Info.bytes, keyData.roundKeys);
    const enc2 = AES.encrypt(pt2Info.bytes, keyData.roundKeys);
    const ciphertext = enc1[CONSTANTS.ROUNDS].afterKey;
    const dec1 = AES.decrypt(ciphertext, keyData.roundKeys);
    const roundDiffs = enc1.map((rnd, r) => {
      const diff = countBitDiff(rnd.afterKey, enc2[r].afterKey);
      return {
        round: r,
        bytes: diff.bytes,
        bits: diff.bits,
        pct: ((diff.bits / 128) * 100).toFixed(1)
      };
    });
    return {
      pt1Info,
      pt2Info,
      keyInfo,
      pt1: pt1Info.bytes,
      pt2: pt2Info.bytes,
      keyData,
      enc1,
      enc2,
      dec1,
      inDiff: countBitDiff(pt1Info.bytes, pt2Info.bytes),
      outDiff: roundDiffs[CONSTANTS.ROUNDS],
      roundDiffs
    };
  }

  const api = {
    CONSTANTS,
    Format,
    Layout,
    GF,
    TABLES,
    AES,
    analyzeBlockInput,
    analyzeKeyInput,
    countBitDiff,
    getRoundSteps,
    normalizeStepKey,
    computeDependencies,
    computeCellTrace,
    flipSingleBitHex,
    computeAvalanche
  };

  root.AESCore = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
