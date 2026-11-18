(function (root) {
  "use strict";

  const CONSTANTS = {
    ROUNDS: 10,
    WORDS: 44,
    POLY_LOW: 0x1b,
    AFFINE_CONST: 0x63,
    INV_AFFINE_CONST: 0x05,
    AFFINE_SHIFTS: [1, 2, 3, 4],
    INV_AFFINE_SHIFTS: [1, 3, 6],
    DEFAULTS: {
      pt1: "ARABA",
      pt2: "ARABB",
      key: "2B7E151628AED2A6ABF7158809CF4F3C",
      pad: "zero"
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

  const Layout = {
    coord: (idx) => ({ r: idx % 4, c: Math.floor(idx / 4), idx }),
    idx: (r, c) => c * 4 + r,
    shiftSourceCol: (c, r, isEnc) => (isEnc ? (c + r) % 4 : (c - r + 4) % 4)
  };

  const GF = {
    rotLeft8(b, k) {
      return ((b << k) | (b >>> (8 - k))) & 0xff;
    },
    xtime(a) {
      return ((a << 1) ^ ((a & 0x80) ? CONSTANTS.POLY_LOW : 0x00)) & 0xff;
    },
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

  const TABLES = (() => {
    const sbox = new Uint8Array(256);
    const invSbox = new Uint8Array(256);
    const rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    for (let i = 0; i < 256; i++) {
      const val = GF.affineForward(GF.inv(i));
      sbox[i] = val;
      invSbox[val] = i;
    }
    return { sbox, invSbox, rcon };
  })();

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
    const padVal = padMode === "pkcs7" ? (16 - bytes.length) : 0x00;
    while (bytes.length < 16) bytes.push(padVal);
    return { bytes, trimmed, mode: "ascii", charLen: trimmed.length, isTruncated: trimmed.length > 16 };
  }

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

  const AES = {
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
          const rot = [prev[1], prev[2], prev[3], prev[0]];
          const sub = rot.map((b) => TABLES.sbox[b]);
          const rc = TABLES.rcon[i / 4];
          const rconXor = [sub[0] ^ rc, sub[1], sub[2], sub[3]];
          W[i] = prev4.map((b, idx) => b ^ rconXor[idx]);
          logs[i] = { type: "rot", i, prev, prev4, rot, sub, rc, rconXor, word: W[i].slice() };
        } else {
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

    subBytes(s, inv = false) {
      const box = inv ? TABLES.invSbox : TABLES.sbox;
      return s.map((b) => box[b]);
    },

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

    addRoundKey(s, rk) {
      return s.map((b, i) => b ^ rk[i]);
    },

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
    computeAvalanche
  };

  root.AESCore = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
