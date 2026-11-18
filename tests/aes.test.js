"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const Core = require(path.join(ROOT, "aes.js"));
const Prefs = require(path.join(ROOT, "ui-prefs.js"));
const { WORKBENCH_TABS, I18N, escapeHtml, buildRoundCardSpec } = require(path.join(ROOT, "app.js"));

const {
  CONSTANTS,
  Format,
  GF,
  AES,
  analyzeBlockInput,
  analyzeKeyInput,
  getRoundSteps,
  normalizeStepKey,
  computeCellTrace,
  computeAvalanche
} = Core;

describe("AES-128 FIPS-197 cryptographic vectors", () => {
  it("encrypts the official FIPS-197 Appendix B test vector and produces published round keys", () => {
    const pt = analyzeBlockInput("3243f6a8885a308d313198a2e0370734", "pkcs7").bytes;
    const key = analyzeKeyInput("2b7e151628aed2a6abf7158809cf4f3c").bytes;
    const { roundKeys } = AES.expandKey(key);

    assert.equal(Format.hexStr(roundKeys[0]), "2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C");
    assert.equal(Format.hexStr(roundKeys[1]), "A0 FA FE 17 88 54 2C B1 23 A3 39 39 2A 6C 76 05");
    assert.equal(Format.hexStr(roundKeys[10]), "D0 14 F9 A8 C9 EE 25 89 E1 3F 0C C8 B6 63 0C A6");

    const enc = AES.encrypt(pt, roundKeys);
    assert.equal(Format.hexStr(enc[10].afterKey), "39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32");

    const dec = AES.decrypt(enc[10].afterKey, roundKeys);
    assert.deepEqual(dec[10].afterKey, pt);
  });

  it("round-trips edge-case blocks losslessly through decrypt", () => {
    const key = analyzeKeyInput("000102030405060708090a0b0c0d0e0f").bytes;
    const { roundKeys } = AES.expandKey(key);
    const cases = [
      new Array(16).fill(0x00),
      new Array(16).fill(0xff),
      analyzeBlockInput("", "pkcs7").bytes,
      analyzeBlockInput("ARABA", "zero").bytes
    ];
    for (const block of cases) {
      const ct = AES.encrypt(block, roundKeys)[10].afterKey;
      const pt = AES.decrypt(ct, roundKeys)[10].afterKey;
      assert.deepEqual(pt, block);
    }
  });

  it("reproduces the classroom ARABA vs ARABB avalanche curve and ciphertext", () => {
    const { pt1, pt2, key, pad } = CONSTANTS.DEFAULTS;
    const av = computeAvalanche(pt1, pt2, key, pad);
    assert.equal(av.inDiff.bits, 2);
    assert.deepEqual(av.roundDiffs.map((d) => d.bits), [2, 23, 71, 66, 66, 58, 60, 65, 58, 72, 65]);
    assert.equal(Format.hexStr(av.enc1[10].afterKey), "EA 38 5F A9 15 11 6B 6D 7C 3A EB A0 1F A0 0C C4");
  });
});

describe("Input analyzers, preferences, and HTML escaping", () => {
  it("classifies hex vs ASCII, empty input, and truncation accurately", () => {
    const hexIn = analyzeBlockInput("  3243f6a8885a308d313198a2e0370734 ", "pkcs7");
    assert.equal(hexIn.mode, "hex");
    assert.equal(hexIn.bytes[0], 0x32);

    const longIn = analyzeBlockInput("12345678901234567890", "zero");
    assert.equal(longIn.mode, "ascii");
    assert.equal(longIn.isTruncated, true);
    assert.equal(longIn.bytes.length, 16);

    const emptyPkcs7 = analyzeBlockInput("", "pkcs7");
    assert.deepEqual(emptyPkcs7.bytes, new Array(16).fill(0x10));

    const dirtyKey = analyzeKeyInput("2B 7E GG");
    assert.equal(dirtyKey.hasInvalidChars, true);
    assert.equal(dirtyKey.isShort, true);
    assert.equal(dirtyKey.bytes.length, 16);
  });

  it("satisfies GF(2^8) zero convention and multiplicative inverse property", () => {
    assert.equal(GF.inv(0), 0);
    assert.equal(GF.mul(0x57, GF.inv(0x57)), 1);
    assert.equal(GF.mul(0x6a, GF.inv(0x6a)), 1);
  });

  it("builds safe cross-page URLs and honors URL query overrides over stored prefs", () => {
    assert.equal(Prefs.buildHref("sunum.html", { lang: "en", theme: "light" }), "sunum.html?lang=en&theme=light");
    assert.equal(Prefs.buildHref("index.html?tab=enc&present=1", { lang: "tr", theme: "dark" }), "index.html?tab=enc&present=1&lang=tr&theme=dark");

    const origStorage = globalThis.localStorage;
    try {
      const store = new Map([["aes_present", "true"], ["aes_lang", "en"], ["aes_theme", "light"]]);
      globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null) };

      const overridden = Prefs.readBootPrefs("?present=0&lang=tr&theme=dark");
      assert.equal(overridden.present, false);
      assert.equal(overridden.lang, "tr");
      assert.equal(overridden.theme, "dark");

      const fallback = Prefs.readBootPrefs("");
      assert.equal(fallback.present, true);
      assert.equal(fallback.lang, "en");
      assert.equal(fallback.theme, "light");
    } finally {
      globalThis.localStorage = origStorage;
    }
  });

  it("escapes unsafe HTML characters cleanly", () => {
    assert.equal(escapeHtml(`<script>"a"&'b'</script>`), "&lt;script&gt;&quot;a&quot;&amp;&#39;b&#39;&lt;/script&gt;");
  });
});

describe("State-flow step normalization and causal cell tracing", () => {
  it("defines exact round pipelines and normalizes invalid round/step query combinations", () => {
    assert.deepEqual(getRoundSteps(0, true), ["input", "rk", "afterKey"]);
    assert.deepEqual(getRoundSteps(1, true), ["input", "afterSub", "afterShift", "afterMix", "afterKey"]);
    assert.deepEqual(getRoundSteps(10, true), ["input", "afterSub", "afterShift", "afterKey"]);
    assert.deepEqual(getRoundSteps(1, false), ["input", "afterShift", "afterSub", "afterKey", "afterMix"]);
    assert.deepEqual(getRoundSteps(10, false), ["input", "afterShift", "afterSub", "afterKey"]);

    assert.equal(normalizeStepKey(0, "afterSub", true), "afterKey");
    assert.equal(normalizeStepKey(10, "afterMix", true), "afterSub");
    assert.equal(normalizeStepKey(0, "afterMix", false), "afterKey");
    assert.equal(normalizeStepKey(10, "afterMix", false), "afterSub");
    assert.equal(normalizeStepKey(3, "afterMix", true), "afterMix");
  });

  it("computes accurate causal dependencies across ShiftRows, MixColumns, and Key expansion", () => {
    const av = computeAvalanche(CONSTANTS.DEFAULTS.pt1, CONSTANTS.DEFAULTS.pt2, CONSTANTS.DEFAULTS.key, "zero");

    const shiftTrace = computeCellTrace({ rData: av.enc1[1], step: "afterShift", idx: 1, roundIdx: 1, isEnc: true, keyData: av.keyData });
    assert.equal(shiftTrace.dep.sourceStep, "afterSub");
    assert.deepEqual([...shiftTrace.dep.sourceIndices], [5]);
    assert.equal(shiftTrace.detail.srcCol, 1);

    const mixTrace = computeCellTrace({ rData: av.enc1[1], step: "afterMix", idx: 6, roundIdx: 1, isEnc: true, keyData: av.keyData });
    assert.equal(mixTrace.dep.sourceStep, "afterShift");
    assert.deepEqual([...mixTrace.dep.sourceIndices], [4, 5, 6, 7]);
    assert.deepEqual(mixTrace.detail.coeffs, [1, 1, 2, 3]);

    const invMixTrace = computeCellTrace({ rData: av.dec1[1], step: "afterMix", idx: 4, roundIdx: 1, isEnc: false, keyData: av.keyData });
    assert.equal(invMixTrace.dep.sourceStep, "afterKey");
    assert.deepEqual([...invMixTrace.dep.sourceIndices], [4, 5, 6, 7]);

    for (const isEnc of [true, false]) {
      const rounds = isEnc ? av.enc1 : av.dec1;
      for (let roundIdx = 0; roundIdx <= CONSTANTS.ROUNDS; roundIdx++) {
        for (const step of getRoundSteps(roundIdx, isEnc)) {
          const spec = buildRoundCardSpec(step, rounds[roundIdx], roundIdx, isEnc);
          assert.ok(spec && spec.title && spec.desc);
          for (let idx = 0; idx < 16; idx++) {
            const trace = computeCellTrace({ rData: rounds[roundIdx], step, idx, roundIdx, isEnc, keyData: av.keyData });
            assert.ok(trace.detail.kind);
          }
        }
      }
    }
  });
});

describe("Bilingual i18n & cross-file presentation contracts", () => {
  it("keeps TR and EN workbench dictionaries strictly symmetric", () => {
    const trKeys = Object.keys(I18N.tr).sort();
    const enKeys = Object.keys(I18N.en).sort();
    assert.deepEqual(trKeys, enKeys);
  });

  it("keeps HTML defaults aligned with domain constants and removes stale artifacts", () => {
    const slidesHtml = fs.readFileSync(path.join(ROOT, "sunum.html"), "utf8");
    const indexHtml = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
    const styleCss = fs.readFileSync(path.join(ROOT, "style.css"), "utf8");
    const tokensCss = fs.readFileSync(path.join(ROOT, "tokens.css"), "utf8");

    assert.ok(indexHtml.includes(`id="pt1-input" value="${CONSTANTS.DEFAULTS.pt1}"`));
    assert.ok(indexHtml.includes(`id="pt2-input" value="${CONSTANTS.DEFAULTS.pt2}"`));
    assert.ok(indexHtml.includes(`id="key-input" value="${CONSTANTS.DEFAULTS.key}"`));

    assert.equal(/data-speaker-|data-role=/.test(slidesHtml), false);
    assert.equal(/prep-state-table/.test(styleCss + indexHtml), false);

    for (const [name, content] of Object.entries({ "sunum.html": slidesHtml, "index.html": indexHtml, "style.css": styleCss, "tokens.css": tokensCss })) {
      assert.equal(/C:\\Users\\/i.test(content), false, `Found hardcoded local path in ${name}`);
    }

    const domKeys = new Set([...slidesHtml.matchAll(/data-i18n="([^"]+)"/g)].map((m) => m[1]));
    const enMatch = slidesHtml.match(/const SLIDE_EN_MAP = (\{[\s\S]*?\n    \});/);
    assert.ok(enMatch, "SLIDE_EN_MAP definition missing in sunum.html");
    const enMap = Function(`return (${enMatch[1]});`)();
    const computedEnKeys = new Set(["s1.m3v", "s1.m3l", "s8.st0v", "s8.st1v", "s8.st2v", "s8.st10v"]);
    for (const k of domKeys) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(enMap, k) || computedEnKeys.has(k),
        `Missing English slide translation key: ${k}`
      );
    }

    const labHrefs = [...slidesHtml.matchAll(/href="(index\.html[^"]*)"/g)].map((m) => m[1]);
    assert.ok(labHrefs.length >= 4);
    for (const href of labHrefs) {
      const qs = href.split("?")[1] || "";
      const params = new URLSearchParams(qs);
      const tab = params.get("tab");
      if (tab) assert.ok(WORKBENCH_TABS.includes(tab), `Invalid deep-link tab in sunum.html: ${tab}`);
      const round = params.get("round");
      if (round !== null) {
        const rNum = Number(round);
        assert.ok(Number.isInteger(rNum) && rNum >= 0 && rNum <= CONSTANTS.ROUNDS);
      }
    }
  });
});
