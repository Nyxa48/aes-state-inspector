"use strict";

/* 1. GF(2^8) SONLU CİSİM ARİTMETİĞİ VE TABLO ÜRETİMİ / FINITE FIELD & TABLES */
const GF = {
  xtime(a) {
    return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00)) & 0xff;
  },
  mul(a, b) {
    let res = 0, cur = a & 0xff;
    for (let i = 0; i < 8; i++) {
      if ((b >> i) & 1) res ^= cur;
      cur = this.xtime(cur);
    }
    return res & 0xff;
  },
  inv(a) {
    if (a === 0) return 0;
    for (let x = 1; x < 256; x++) if (this.mul(a, x) === 1) return x;
    return 0;
  }
};

const TABLES = (() => {
  const sbox = new Uint8Array(256);
  const invSbox = new Uint8Array(256);
  const rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  for (let i = 0; i < 256; i++) {
    const inv = GF.inv(i);
    let aff = inv;
    for (let k = 1; k <= 4; k++) aff ^= ((inv << k) | (inv >>> (8 - k))) & 0xff;
    const val = (aff ^ 0x63) & 0xff;
    sbox[i] = val;
    invSbox[val] = i;
  }
  return { sbox, invSbox, rcon };
})();

/* 2. AES-128 MOTORU / CORE ENGINE */
const AES = {
  expandKey(key) {
    const W = [], logs = [];
    for (let i = 0; i < 4; i++) {
      W[i] = key.slice(i * 4, i * 4 + 4);
      logs[i] = { type: "init", i, word: W[i].slice() };
    }
    for (let i = 4; i < 44; i++) {
      const prev = W[i - 1].slice(), prev4 = W[i - 4].slice();
      if (i % 4 === 0) {
        const rot = [prev[1], prev[2], prev[3], prev[0]];
        const sub = rot.map(b => TABLES.sbox[b]);
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
    for (let r = 0; r <= 10; r++) {
      const rk = [];
      for (let c = 0; c < 4; c++) rk.push(...W[r * 4 + c]);
      roundKeys.push(rk);
    }
    return { W, logs, roundKeys };
  },
  subBytes(s, inv = false) {
    const box = inv ? TABLES.invSbox : TABLES.sbox;
    return s.map(b => box[b]);
  },
  shiftRows(s, inv = false) {
    const out = new Array(16);
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) {
        const srcCol = inv ? (c - r + 4) % 4 : (c + r) % 4;
        out[c * 4 + r] = s[srcCol * 4 + r];
      }
    }
    return out;
  },
  mixColumns(s, inv = false) {
    const out = new Array(16);
    const M = inv
      ? [[0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d], [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]]
      : [[0x02, 0x03, 0x01, 0x01], [0x01, 0x02, 0x03, 0x01], [0x01, 0x01, 0x02, 0x03], [0x03, 0x01, 0x01, 0x02]];
    for (let c = 0; c < 4; c++) {
      const col = s.slice(c * 4, c * 4 + 4);
      for (let r = 0; r < 4; r++) {
        out[c * 4 + r] = GF.mul(M[r][0], col[0]) ^ GF.mul(M[r][1], col[1]) ^ GF.mul(M[r][2], col[2]) ^ GF.mul(M[r][3], col[3]);
      }
    }
    return out;
  },
  addRoundKey(s, rk) {
    return s.map((b, i) => b ^ rk[i]);
  },
  encrypt(pt, rks) {
    const rounds = [];
    let state = this.addRoundKey(pt, rks[0]);
    rounds.push({ round: 0, input: pt.slice(), rk: rks[0].slice(), afterKey: state.slice() });
    for (let r = 1; r <= 10; r++) {
      const input = state.slice();
      const afterSub = this.subBytes(input, false);
      const afterShift = this.shiftRows(afterSub, false);
      const afterMix = r < 10 ? this.mixColumns(afterShift, false) : null;
      const afterKey = this.addRoundKey(r < 10 ? afterMix : afterShift, rks[r]);
      state = afterKey;
      rounds.push({ round: r, input, afterSub, afterShift, afterMix, rk: rks[r].slice(), afterKey });
    }
    return rounds;
  },
  decrypt(ct, rks) {
    const rounds = [];
    let state = this.addRoundKey(ct, rks[10]);
    rounds.push({ round: 10, input: ct.slice(), rk: rks[10].slice(), afterKey: state.slice() });
    for (let r = 9; r >= 0; r--) {
      const input = state.slice();
      const afterShift = this.shiftRows(input, true);
      const afterSub = this.subBytes(afterShift, true);
      const afterKey = this.addRoundKey(afterSub, rks[r]);
      const afterMix = r > 0 ? this.mixColumns(afterKey, true) : null;
      state = r > 0 ? afterMix : afterKey;
      rounds.push({ round: r, input, afterShift, afterSub, rk: rks[r].slice(), afterKey, afterMix });
    }
    return rounds;
  }
};

/* 3. FORMAT YARDIMCILARI / FORMATTING */
const hex2 = b => b.toString(16).toUpperCase().padStart(2, "0");
const bin8 = b => b.toString(2).padStart(8, "0");
const hexStr = arr => arr.map(hex2).join(" ");
const escapeHtml = s => String(s)
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;");

function parseBlock(raw, padMode) {
  const s = raw.trim();
  if (/^[0-9a-fA-F]{32}$/.test(s)) {
    const out = [];
    for (let i = 0; i < 32; i += 2) out.push(parseInt(s.slice(i, i + 2), 16));
    return out;
  }
  const bytes = [];
  for (let i = 0; i < Math.min(s.length, 16); i++) bytes.push(s.charCodeAt(i) & 0xff);
  const padLen = 16 - bytes.length;
  const padVal = padMode === "pkcs7" ? (padLen || 16) : 0x00;
  while (bytes.length < 16) bytes.push(padVal);
  return bytes;
}

function parseKey(raw) {
  const clean = raw.replace(/[^0-9a-fA-F]/g, "").padEnd(32, "0").slice(0, 32);
  const out = [];
  for (let i = 0; i < 32; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
  return out;
}

function countBitDiff(a, b) {
  let bits = 0, bytes = 0;
  for (let i = 0; i < 16; i++) {
    const x = a[i] ^ b[i];
    if (x !== 0) {
      bytes++;
      for (let k = 0; k < 8; k++) if ((x >> k) & 1) bits++;
    }
  }
  return { bits, bytes };
}

/* 4. ÇİFT DİL SÖZLÜĞÜ / I18N */
const I18N = {
  tr: {
    pageTitle: "AES-128 İnteraktif Kriptoloji Laboratuvarı",
    skipLink: "İçeriğe atla",
    appTitle: "AES-128 Simetrik Blok Şifreleme Laboratuvarı",
    slidesLink: "Sunum Slaytları",
    presentBtn: "Sunum Modu",
    themeLight: "Açık Tema",
    themeDark: "Koyu Tema",
    lblPt1: "Ana düz metin (ASCII veya 32 hex)",
    lblPt2: "Karşılaştırma metni (Çığ etkisi)",
    lblPad: "Blok dolgusu (16 bayt)",
    optZero: "Sıfır dolgusu (0x00)",
    optPkcs7: "PKCS#7 standart dolgusu",
    lblKey: "128-bit gizli anahtar (32 hex)",
    hintHexBlock: "32 hex · Tam 16 bayt blok",
    hintAsciiBlock: (n) => `ASCII · ${n}/16 bayt (kalanı dolduruldu)`,
    hintTruncBlock: (n) => `İlk 16 bayt alındı (${n} karakter girildi)`,
    hintPadZero: "Kalan baytlar 0x00 ile doldurulur",
    hintPadPkcs7: "Eksik bayt sayısı kadar aynı değer yazılır",
    hintKeyOk: "32/32 hex · Geçerli 128-bit anahtar",
    hintKeyShort: (n) => `${n}/32 hex · Eksik kısım 00 ile tamamlandı`,
    hintKeyDirty: (n) => `Hex dışı karakterler yoksayıldı · ${n}/32 hex`,
    navAria: "Çalışma sekmeleri ve tur seçimi",
    tabPrep: "Adım 0: Blok Hazırlama",
    tabEnc: "Şifreleme (Tur 0–10)",
    tabKey: "Anahtar Türetme",
    tabDec: "Deşifreleme",
    khTabs: "Sekme",
    khStep: "Tur / Kelime",
    khNotes: "Sunum Notu",
    khTheme: "Tema",
    notesOpenAll: "Tüm Notları Aç",
    notesCloseAll: "Notları Kapat",
    diffToggle: (name) => `<strong>${name}</strong> farklarını matriste işaretle`,
    noteTitle: "Sunum Notu",
    prepNoteMeta: "Konuşmacı 1 · Adım 0 ipuçları",
    roundNoteMeta: "Konuşmacı 2 · Tur akışı ipuçları",
    inspNoteMeta: "Olası soru ve tahta kanıtı",
    keyNoteMeta: "Konuşmacı 1 · Key Schedule ipuçları",
    prepGuide: "<strong>Blok hazırlama özeti:</strong> Giriş metni ASCII baytlarına dönüştürülür, seçilen dolgu yöntemiyle 16 bayta (128 bit) tamamlanır ve 4×4 durum matrisine sütun-öncelikli (column-major) sırayla yerleştirilir.",
    prepNotes: `<ul>
      <li><strong>Sütun-öncelikli dizilim:</strong> İlk dört bayt (<code>A R A B</code>) birinci satıra değil, birinci sütuna yukarıdan aşağıya yazılır. 5. bayt olan ikinci <code>A</code> ise <code>s[0,1]</code> hücresine geçer.</li>
      <li><strong>2 bitlik fark vurgusu:</strong> <code>A</code> (<code>0x41 = 01000001</code>) ile <code>B</code> (<code>0x42 = 01000010</code>) arasında yalnızca 2 bit fark vardır; sağdaki çığ etkisi tablosu bu farkın 2. tur sonunda tüm 16 bayta yayıldığını gösterir.</li>
    </ul>`,
    keyGuide: "<strong>Anahtar genişletme mantığı:</strong> 16 baytlık başlangıç anahtarından 11 tur için toplam 44 adet 32-bit kelime (<code>W[0]..W[43]</code>) üretilir. İndeksi 4'ün katı olan kelimelerde sırasıyla <code>RotWord</code>, <code>SubWord</code> ve <code>Rcon</code> XOR işlemleri uygulanır.",
    keyNotes: `<ul>
      <li><strong>Neden 44 kelime?</strong> Her 4×4 tur anahtarı 4 sütundan (kelimeden) oluşur. Başlangıç (Tur 0) + 10 şifreleme turu = 11 tur × 4 sütun = 44 kelime.</li>
      <li><strong><code>W[4]</code> örneği:</strong> Tablodan <code>W[4]</code> butonunu seçip sağdaki 6 adımlı hesabı gösterin: <code>W[3]</code> 1 bayt sola döner, S-Box'a girer, <code>Rcon[1] = 01 00 00 00</code> ile XOR'lanır ve <code>W[0]</code> ile birleştirilir.</li>
    </ul>`,
    inspTitle: "Hücre Matematiği Denetçisi",
    sboxTitle: "S-Box Arama Tablosu (16×16)",
    invSboxTitle: "InvS-Box Arama Tablosu (16×16)",
    sboxHint: "İlk nibble satır, ikinci nibble sütun",
    keyTableTitle: "11 Tur Anahtarı (44 Kelime)",
    keyTableHint: "Hesabı incelemek için bir W[i] sütunu seçin",
    bannerMain: (name) => `Ana metin (${name}) · Giriş ve Tur 10 çıktısı`,
    bannerCmp: (name) => `Karşılaştırma (${name}) · Değişen baytlar`,
    bannerInTitle: "Ana metinde",
    bannerIn: "Giriş",
    bannerOut: "Çıktı",
    avalIn: "Giriş farkı",
    avalOut: "Çıkış farkı",
    fmtBytes: (n) => `${n} bayt`,
    fmtBits: (n) => `${n}/128 bit`,
    fmtPct: (p) => `%${p}`,
    unitByte: "bayt",
    prepAsciiHead: (a, b) => `1. ASCII ve onaltılık (Hex) dönüşüm (${a} vs ${b})`,
    colPos: "Konum",
    colAscii: (a) => `${a} (ASCII · 10'luk · Hex)`,
    colDiff: "Fark",
    padLbl: "Dolgu",
    sameLbl: "Aynı",
    bitDiffLbl: (n) => `${n} bit farklı`,
    byteWord: "Bayt",
    prepStateTitle: "2. 4×4 durum (State) matrisi",
    prepStateBadge: "Sütun-öncelikli dizilim",
    prepStateSub: "İlk 4 bayt birinci satıra değil, birinci sütuna yukarıdan aşağıya yerleştirilir.",
    prepAvalTitle: "3. Tur bazlı çığ etkisi",
    prepAvalBadge: "Bit yayılma hızı",
    colStage: "Aşama",
    colChangedBytes: "Değişen bayt",
    colChangedBits: "Değişen bit oranı",
    stageStart: "Başlangıç (Tur 0)",
    stageEnd: (r) => `Tur ${r} sonu`,
    rndEnc0: "Başlangıç (Tur 0)",
    rndEncN: (i) => `Tur ${i}`,
    rndDec0: "Başlangıç (Tur 10)",
    rndDecN: (i) => `Ters Adım ${i} (Tur ${10 - i})`,
    stepInput: "Tur Girişi",
    stepRk: "Tur Anahtarı",
    stepSub: "SubBytes",
    stepInvSub: "InvSubBytes",
    stepShift: "ShiftRows",
    stepInvShift: "InvShiftRows",
    stepMix: "MixColumns",
    stepInvMix: "InvMixColumns",
    stepKey: "AddRoundKey",
    guideEnc0: "<strong>Başlangıç adımı (Tur 0):</strong> Düz metin matrisi ile başlangıç anahtarı bayt bazında XOR işlemine sokulur (<code>AddRoundKey</code>). Bu aşamada yerine koyma veya kaydırma uygulanmaz.",
    guideDec0: "<strong>Deşifreleme başlangıcı:</strong> Şifreli metin, 10. tur anahtarıyla XOR'lanarak ters dönüşüm zinciri başlatılır.",
    noteEnc0: "<ul><li><strong>Neden Tur 0 var?</strong> Başlangıçta <code>AddRoundKey</code> yapılmazsa ilk turun <code>SubBytes</code> ve <code>ShiftRows</code> adımları anahtar bilmeyen biri tarafından da geri alınabilir; anahtar karıştırma ilk adımdan itibaren gizlilik sağlar.</li></ul>",
    noteDec0: "<ul><li><strong>Simetrik XOR özelliği:</strong> 10. tur sonunda en son <code>AddRoundKey(K10)</code> uygulandığı için geri açmada ilk işlem yine aynı <code>K10</code> anahtarıyla XOR almaktır.</li></ul>",
    guideEncN: (r, hasMix) => `<strong>Tur ${r} akışı:</strong> 1. <strong>SubBytes</strong> (doğrusal olmayan değişim) → 2. <strong>ShiftRows</strong> (satır kaydırma) → ${hasMix ? "3. <strong>MixColumns</strong> (sütun yayılımı) → 4." : "3."} <strong>AddRoundKey</strong> (Tur ${r} anahtarı ile XOR).`,
    noteEncMix: "<ul><li><strong>Karışıklık ve yayılma:</strong> <code>SubBytes</code> karışıklık (confusion), <code>ShiftRows</code> ve <code>MixColumns</code> ise yayılma (diffusion) sağlar.</li><li><strong>Tur 1 ve Tur 2 farkı:</strong> Tur 1'de kırmızı fark yalnızca 1. sütunda (4 bayt) toplanır; Tur 2'deki <code>ShiftRows</code> bu baytları 4 farklı sütuna dağıtır ve <code>MixColumns</code> tüm 16 baytı değiştirir.</li></ul>",
    noteEncLast: "<ul><li><strong>10. turda neden MixColumns yok?</strong> Son turda yapılan <code>MixColumns</code> kriptografik güvenlik eklemez çünkü bir saldırgan veya deşifreleyici anahtar bilmeden bu doğrusal matrisi tersine çevirebilir; çıkarılması şifreleme ve deşifrelemeyi simetrik kılar.</li></ul>",
    guideDecN: (r, hasMix) => `<strong>Ters adım (Tur ${r}):</strong> Şifreleme işlemleri ters sırada ve ters operatörlerle uygulanır: <strong>InvShiftRows</strong> → <strong>InvSubBytes</strong> → <strong>AddRoundKey</strong>${hasMix ? " → <strong>InvMixColumns</strong>" : ""}.`,
    noteDecN: "<ul><li><strong>Ters matris katsayıları:</strong> <code>MixColumns</code> içindeki <code>{02, 03, 01, 01}</code> matrisinin GF(2⁸) üzerindeki tersi <code>{0E, 0B, 0D, 09}</code> matrisidir.</li></ul>",
    c0InTitle: "1. Giriş Matrisi",
    c0InDesc: "İşleme giren 16 baytlık durum",
    c0RkTitle: "2. Tur Anahtarı",
    c0RkEnc: "Başlangıç anahtarı (Key 0)",
    c0RkDec: "Tur 10 anahtarı",
    c0KeyTitle: "3. AddRoundKey",
    c0KeyDesc: "Giriş ⊕ Anahtar (bayt bazında XOR)",
    cEncInTitle: "0. Tur Girişi",
    cEncInDesc: (p) => `Tur ${p} çıkış durumu`,
    cEncSubTitle: "1. SubBytes",
    cEncSubDesc: "16×16 S-Box yerine koyma",
    cEncShiftTitle: "2. ShiftRows",
    cEncShiftDesc: "Satırlar 0, 1, 2, 3 birim sola kayar",
    cEncMixTitle: "3. MixColumns",
    cEncMixDesc: "Sütundaki 4 baytın GF(2⁸) çarpımı",
    cEncKeyTitle: (hasMix) => hasMix ? "4. AddRoundKey" : "3. AddRoundKey (Son Tur)",
    cEncKeyDesc: (r) => `Tur ${r} anahtarıyla XOR`,
    cDecInTitle: "0. Giriş",
    cDecInDesc: "Önceki ters adımdan gelen durum",
    cDecShiftTitle: "1. InvShiftRows",
    cDecShiftDesc: "Satırlar 0, 1, 2, 3 birim sağa kayar",
    cDecSubTitle: "2. InvSubBytes",
    cDecSubDesc: "Ters S-Box yerine koyma",
    cDecKeyTitle: "3. AddRoundKey",
    cDecKeyDesc: (r) => `Tur ${r} anahtarıyla XOR`,
    cDecMixTitle: "4. InvMixColumns",
    cDecMixDesc: "Ters matris (0E, 0B, 0D, 09) çarpımı",
    inspCoord: (r, c, n, lbl) => `s[${r},${c}] · ${n}. bayt · ${lbl}`,
    inspSubBox: (inB, boxName, hi, lo, outB) => `<strong>Tablo kesişimi:</strong> Girdi baytı <strong>${inB}</strong> → ${boxName} üzerinde <strong>${hi}</strong> satırı, <strong>${lo}</strong> sütunu → Sonuç: <strong>${outB}</strong>`,
    inspSubHead: "GF(2⁸) üretim aşamaları",
    inspBinCol: "8-bit ikilik",
    inspSubR1: "1. Girdi baytı",
    inspSubR2: "2. Çarpımsal ters (mod 0x11B)",
    inspSubR3: "3. Afin dönüşüm + 0x63 XOR",
    inspSubNote: "<ul><li><strong>Hızlı tahta anlatımı:</strong> S-Box sabit ezberlenmiş bir tablo değildir; <code>0x11B</code> (x⁸ + x⁴ + x³ + x + 1) polinomu altında çarpımsal ters alınıp afin matris ve <code>0x63</code> sabiti ile sabit noktası (<code>S(x)=x</code>) olmayacak şekilde üretilir.</li></ul>",
    inspShiftBox: (row1, r, dir, srcCol, val, c) => `<strong>Satır kaydırma:</strong> ${row1}. satır (indeks ${r}) toplam <strong>${r}</strong> birim ${dir} kaydırılır.<br><strong>s[${r},${srcCol}]</strong> hücresindeki <strong>${val}</strong> baytı <strong>s[${r},${c}]</strong> konumuna taşınır.`,
    dirLeft: "sola",
    dirRight: "sağa",
    inspShiftNote: "<ul><li><strong>Neden ShiftRows yapılır?</strong> Her sütun birbirinden bağımsız olsaydı AES 4 ayrı 32-bit şifre gibi davranırdı. Satır kaydırma, bir baytı farklı sütunlara taşıyarak <code>MixColumns</code> ile tüm bloğa yayılmasını sağlar.</li></ul>",
    mixUnit: (b) => `Birim çarpım: ${b}`,
    mixDouble: (sh, msb, p) => `1 bit sola kaydır: ${sh} ${msb ? `(MSB=1 taşması → 1B ile XOR: ${sh} ⊕ 1B = ${p})` : "(Taşma yok)"}`,
    mixTriple: (b, x2, p) => `(02 • ${b}) ⊕ ${b} = ${x2} ⊕ ${b} = ${p}`,
    mixPoly: (k, b, p) => `GF(2⁸) polinomsal çarpım: ${k} • ${b} = ${p}`,
    mixEqTitle: (c) => `Sütun ${c} denklemi:`,
    mixColMul: "Çarpım",
    mixColStep: "Polinomsal çarpım adımı",
    mixSum: "4 terimin XOR toplamı",
    inspMixNote: "<ul><li><strong><code>0x1B</code> kuralı:</strong> <code>02</code> ile çarparken sayının en sol biti (MSB) <code>1</code> ise 8 bitten taşma olur; indirgenemez polinom olan <code>0x11B</code>'nin alt 8 biti (<code>0x1B</code>) ile XOR alınır. <code>03</code> ile çarpım ise <code>(02•x) ⊕ x</code> şeklinde hesaplanır.</li></ul>",
    inspKeyBox: "<strong>AddRoundKey (XOR):</strong> Eşit bitler 0, farklı bitler 1 üretir. Aynı tur anahtarıyla ikinci kez XOR uygulandığında girdi değeri geri elde edilir.",
    colVal: "Değer",
    inspKeyR1: (r, c) => `Durum baytı s[${r},${c}]`,
    inspKeyR2: (r, c) => `Anahtar baytı k[${r},${c}]`,
    inspKeyRes: (a, k) => `XOR sonucu (${a} ⊕ ${k})`,
    inspKeyNote: "<ul><li><strong>Neden toplama değil XOR?</strong> XOR bit bazında kendi kendinin tersidir (<code>(A ⊕ K) ⊕ K = A</code>) ve taşıma (carry) üretmediği için sabit zamanda donanım dostu çalışır.</li></ul>",
    keyTabCols: ["Tur", "1. Sütun", "2. Sütun", "3. Sütun", "4. Sütun", "16 bayt tur anahtarı"],
    keyRoundLbl: (r) => `Tur ${r}`,
    keyInspTitle: (w) => `W[${w}] Sütunu Türetimi`,
    keyInitBox: (i, w) => `<strong>W[${i}] = [${w}]</strong><br>İlk 4 kelime (W[0]..W[3]) doğrudan 128-bit başlangıç gizli anahtarından kopyalanır.`,
    keyRotBox: (i) => `<strong>4'ün katı kelime türetimi:</strong> W[${i}] = W[${i - 4}] ⊕ SubWord(RotWord(W[${i - 1}])) ⊕ Rcon[${i / 4}]`,
    keyRotR1: (i) => `1. Önceki kelime W[${i - 1}]`,
    keyRotR2: "2. RotWord (1 bayt sola döndür)",
    keyRotR3: "3. SubWord (S-Box dönüşümü)",
    keyRotR4: (r, rc) => `4. Rcon[${r}] (${rc} 00 00 00) ile XOR`,
    keyRotR5: (i) => `5. W[${i - 4}] kelimesi`,
    keyRotR6: (i) => `6. Sonuç W[${i}] (Adım 4 ⊕ Adım 5)`,
    keyXorBox: (i) => `<strong>Standart kelime türetimi:</strong> W[${i}] = W[${i - 4}] ⊕ W[${i - 1}]`,
    keyXorR1: (i) => `W[${i - 4}] kelimesi`,
    keyXorR2: (i) => `W[${i - 1}] kelimesi`,
    keyXorR3: (i) => `XOR sonucu W[${i}]`
  },
  en: {
    pageTitle: "AES-128 Interactive Cryptography Workbench",
    skipLink: "Skip to content",
    appTitle: "AES-128 Symmetric Block Cipher Laboratory",
    slidesLink: "Presentation Slides",
    presentBtn: "Presentation Mode",
    themeLight: "Light Theme",
    themeDark: "Dark Theme",
    lblPt1: "Primary plaintext (ASCII or 32 hex)",
    lblPt2: "Comparison plaintext (Avalanche effect)",
    lblPad: "Block padding (16 bytes)",
    optZero: "Zero padding (0x00)",
    optPkcs7: "PKCS#7 standard padding",
    lblKey: "128-bit secret key (32 hex)",
    hintHexBlock: "32 hex · Exact 16-byte block",
    hintAsciiBlock: (n) => `ASCII · ${n}/16 bytes (remainder padded)`,
    hintTruncBlock: (n) => `Truncated to 16 bytes (${n} chars entered)`,
    hintPadZero: "Remaining bytes filled with 0x00",
    hintPadPkcs7: "Fills with N copies of padding length N",
    hintKeyOk: "32/32 hex · Valid 128-bit key",
    hintKeyShort: (n) => `${n}/32 hex · Padded with trailing 00`,
    hintKeyDirty: (n) => `Non-hex characters ignored · ${n}/32 hex`,
    navAria: "Workspace tabs and round selector",
    tabPrep: "Step 0: Block Preparation",
    tabEnc: "Encryption (Rounds 0–10)",
    tabKey: "Key Schedule",
    tabDec: "Decryption",
    khTabs: "Tab",
    khStep: "Round / Word",
    khNotes: "Speaker Notes",
    khTheme: "Theme",
    notesOpenAll: "Open All Notes",
    notesCloseAll: "Close Notes",
    diffToggle: (name) => `Highlight <strong>${name}</strong> differences in matrices`,
    noteTitle: "Speaker Note",
    prepNoteMeta: "Speaker 1 · Step 0 talking points",
    roundNoteMeta: "Speaker 2 · Round flow talking points",
    inspNoteMeta: "Board proof & Q&A hint",
    keyNoteMeta: "Speaker 1 · Key Schedule talking points",
    prepGuide: "<strong>Block formatting summary:</strong> Plaintext is converted to ASCII bytes, padded to 16 bytes (128 bits) using the selected scheme, and loaded into the 4×4 state matrix in column-major order.",
    prepNotes: `<ul>
      <li><strong>Column-major layout:</strong> The first four bytes (<code>A R A B</code>) populate Column 0 from top to bottom rather than Row 0. The 5th byte (<code>A</code>) lands at <code>s[0,1]</code>.</li>
      <li><strong>2-bit input delta:</strong> <code>A</code> (<code>0x41 = 01000001</code>) and <code>B</code> (<code>0x42 = 01000010</code>) differ by only 2 bits; the avalanche table on the right tracks how that expands across all 16 bytes by the end of Round 2.</li>
    </ul>`,
    keyGuide: "<strong>Key expansion logic:</strong> A single 16-byte cipher key expands into 44 32-bit words (<code>W[0]..W[43]</code>) covering 11 round keys. Multiples of 4 apply <code>RotWord</code>, <code>SubWord</code>, and an XOR with round constant <code>Rcon</code>.",
    keyNotes: `<ul>
      <li><strong>Why 44 words?</strong> Each 4×4 round key has 4 columns (words). Initial key (Round 0) + 10 rounds = 11 round keys × 4 words = 44 words.</li>
      <li><strong><code>W[4]</code> walkthrough:</strong> Select <code>W[4]</code> in the table to show all 6 steps: <code>W[3]</code> rotates left by 1 byte, passes through the S-Box, XORs with <code>Rcon[1] = 01 00 00 00</code>, and XORs with <code>W[0]</code>.</li>
    </ul>`,
    inspTitle: "Cell Math Inspector",
    sboxTitle: "S-Box Lookup Table (16×16)",
    invSboxTitle: "InvS-Box Lookup Table (16×16)",
    sboxHint: "High nibble = row, low nibble = column",
    keyTableTitle: "11 Round Keys (44 Words)",
    keyTableHint: "Select any W[i] column to inspect its derivation",
    bannerMain: (name) => `Primary (${name}) · Input & Round 10 ciphertext`,
    bannerCmp: (name) => `Comparison (${name}) · Changed bytes`,
    bannerInTitle: "In primary",
    bannerIn: "Input",
    bannerOut: "Output",
    avalIn: "Input diff",
    avalOut: "Output diff",
    fmtBytes: (n) => `${n} ${n === 1 ? "byte" : "bytes"}`,
    fmtBits: (n) => `${n}/128 ${n === 1 ? "bit" : "bits"}`,
    fmtPct: (p) => `${p}%`,
    unitByte: "bytes",
    prepAsciiHead: (a, b) => `1. ASCII to Hex conversion (${a} vs ${b})`,
    colPos: "Position",
    colAscii: (a) => `${a} (ASCII · Dec · Hex)`,
    colDiff: "Diff",
    padLbl: "Pad",
    sameLbl: "Match",
    bitDiffLbl: (n) => `${n} bits differ`,
    byteWord: "Byte",
    prepStateTitle: "2. 4×4 state matrix",
    prepStateBadge: "Column-major order",
    prepStateSub: "The first 4 bytes fill Column 0 from top to bottom, not Row 0.",
    prepAvalTitle: "3. Round-by-round avalanche",
    prepAvalBadge: "Bit diffusion rate",
    colStage: "Stage",
    colChangedBytes: "Changed bytes",
    colChangedBits: "Bit diff ratio",
    stageStart: "Initial (Round 0)",
    stageEnd: (r) => `End of Round ${r}`,
    rndEnc0: "Initial (Round 0)",
    rndEncN: (i) => `Round ${i}`,
    rndDec0: "Initial (Round 10)",
    rndDecN: (i) => `Inv Step ${i} (Round ${10 - i})`,
    stepInput: "Round Input",
    stepRk: "Round Key",
    stepSub: "SubBytes",
    stepInvSub: "InvSubBytes",
    stepShift: "ShiftRows",
    stepInvShift: "InvShiftRows",
    stepMix: "MixColumns",
    stepInvMix: "InvMixColumns",
    stepKey: "AddRoundKey",
    guideEnc0: "<strong>Initial step (Round 0):</strong> The plaintext state and initial cipher key are combined via bitwise XOR (<code>AddRoundKey</code>). No substitution or row shifting runs here.",
    guideDec0: "<strong>Decryption start:</strong> Ciphertext is XORed with Round 10's key before unwinding the inverse round transformations.",
    noteEnc0: "<ul><li><strong>Why Round 0?</strong> Without an initial <code>AddRoundKey</code>, Round 1's <code>SubBytes</code> and <code>ShiftRows</code> would be invertible without the key; whitening the input ensures secrecy from the start.</li></ul>",
    noteDec0: "<ul><li><strong>Self-inverting XOR:</strong> Encryption finishes with <code>AddRoundKey(K10)</code>, so decryption begins by XORing the exact same <code>K10</code>.</li></ul>",
    guideEncN: (r, hasMix) => `<strong>Round ${r} pipeline:</strong> 1. <strong>SubBytes</strong> (non-linear substitution) → 2. <strong>ShiftRows</strong> (row rotation) → ${hasMix ? "3. <strong>MixColumns</strong> (column mixing) → 4." : "3."} <strong>AddRoundKey</strong> (XOR with Round ${r} key).`,
    noteEncMix: "<ul><li><strong>Confusion & diffusion:</strong> <code>SubBytes</code> provides non-linear confusion, while <code>ShiftRows</code> and <code>MixColumns</code> spread byte changes across the whole block (diffusion).</li><li><strong>Rounds 1 vs 2:</strong> In Round 1, differences stay in Column 1 (4 bytes). In Round 2, <code>ShiftRows</code> spreads them to all 4 columns and <code>MixColumns</code> flips all 16 bytes.</li></ul>",
    noteEncLast: "<ul><li><strong>Why no MixColumns in Round 10?</strong> Without another key addition afterward, a linear <code>MixColumns</code> layer could be inverted without knowing the key; omitting it also keeps encryption and decryption structurally symmetric.</li></ul>",
    guideDecN: (r, hasMix) => `<strong>Inverse step (Round ${r}):</strong> Inverse operators run in reverse order: <strong>InvShiftRows</strong> → <strong>InvSubBytes</strong> → <strong>AddRoundKey</strong>${hasMix ? " → <strong>InvMixColumns</strong>" : ""}.`,
    noteDecN: "<ul><li><strong>Inverse MDS matrix:</strong> In <code>GF(2⁸)</code>, the algebraic inverse of <code>{02, 03, 01, 01}</code> is the matrix <code>{0E, 0B, 0D, 09}</code>.</li></ul>",
    c0InTitle: "1. Input Matrix",
    c0InDesc: "16-byte input state",
    c0RkTitle: "2. Round Key",
    c0RkEnc: "Initial cipher key (Key 0)",
    c0RkDec: "Round 10 key",
    c0KeyTitle: "3. AddRoundKey",
    c0KeyDesc: "Input ⊕ Key (bitwise XOR)",
    cEncInTitle: "0. Round Input",
    cEncInDesc: (p) => `Output from Round ${p}`,
    cEncSubTitle: "1. SubBytes",
    cEncSubDesc: "16×16 S-Box byte lookup",
    cEncShiftTitle: "2. ShiftRows",
    cEncShiftDesc: "Rows shift left by 0, 1, 2, 3",
    cEncMixTitle: "3. MixColumns",
    cEncMixDesc: "Column GF(2⁸) matrix multiplication",
    cEncKeyTitle: (hasMix) => hasMix ? "4. AddRoundKey" : "3. AddRoundKey (Final)",
    cEncKeyDesc: (r) => `XOR with Round ${r} key`,
    cDecInTitle: "0. Input",
    cDecInDesc: "State from previous inverse step",
    cDecShiftTitle: "1. InvShiftRows",
    cDecShiftDesc: "Rows shift right by 0, 1, 2, 3",
    cDecSubTitle: "2. InvSubBytes",
    cDecSubDesc: "Inverse S-Box substitution",
    cDecKeyTitle: "3. AddRoundKey",
    cDecKeyDesc: (r) => `XOR with Round ${r} key`,
    cDecMixTitle: "4. InvMixColumns",
    cDecMixDesc: "Inverse matrix (0E, 0B, 0D, 09)",
    inspCoord: (r, c, n, lbl) => `s[${r},${c}] · Byte ${n} · ${lbl}`,
    inspSubBox: (inB, boxName, hi, lo, outB) => `<strong>Table lookup:</strong> Input byte <strong>${inB}</strong> → ${boxName} row <strong>${hi}</strong>, column <strong>${lo}</strong> → Result: <strong>${outB}</strong>`,
    inspSubHead: "GF(2⁸) derivation stages",
    inspBinCol: "8-bit binary",
    inspSubR1: "1. Input byte",
    inspSubR2: "2. Multiplicative inverse (mod 0x11B)",
    inspSubR3: "3. Affine transform + 0x63 XOR",
    inspSubNote: "<ul><li><strong>Algebraic construction:</strong> The S-Box is not arbitrary; each byte takes its multiplicative inverse modulo <code>0x11B</code> (x⁸ + x⁴ + x³ + x + 1) followed by an affine map + <code>0x63</code> XOR to eliminate fixed points (<code>S(x)=x</code>).</li></ul>",
    inspShiftBox: (row1, r, dir, srcCol, val, c) => `<strong>Row rotation:</strong> Row ${row1} (index ${r}) shifts <strong>${r}</strong> positions ${dir}.<br>Byte <strong>${val}</strong> from <strong>s[${r},${srcCol}]</strong> moves into <strong>s[${r},${c}]</strong>.`,
    dirLeft: "left",
    dirRight: "right",
    inspShiftNote: "<ul><li><strong>Why ShiftRows?</strong> Without row shifts, columns would stay isolated like four independent 32-bit ciphers. Shifting mixes bytes across columns so <code>MixColumns</code> diffuses changes globally.</li></ul>",
    mixUnit: (b) => `Identity multiplication: ${b}`,
    mixDouble: (sh, msb, p) => `Shift left 1 bit: ${sh} ${msb ? `(MSB=1 overflow → XOR 1B: ${sh} ⊕ 1B = ${p})` : "(No overflow)"}`,
    mixTriple: (b, x2, p) => `(02 • ${b}) ⊕ ${b} = ${x2} ⊕ ${b} = ${p}`,
    mixPoly: (k, b, p) => `GF(2⁸) polynomial product: ${k} • ${b} = ${p}`,
    mixEqTitle: (c) => `Column ${c} equation:`,
    mixColMul: "Product",
    mixColStep: "Finite-field reduction step",
    mixSum: "XOR sum of 4 terms",
    inspMixNote: "<ul><li><strong>Why <code>0x1B</code>?</strong> Multiplying by <code>02</code> shifts left by 1 bit; if <code>MSB = 1</code>, the 9th bit overflows modulo <code>0x11B</code>, so reducing means XORing the lower 8 bits with <code>0x1B</code>. Multiplying by <code>03</code> equals <code>(02•x) ⊕ x</code>.</li></ul>",
    inspKeyBox: "<strong>AddRoundKey (XOR):</strong> Equal bits yield 0, differing bits yield 1. Applying XOR again with the same key byte restores the original state byte.",
    colVal: "Value",
    inspKeyR1: (r, c) => `State byte s[${r},${c}]`,
    inspKeyR2: (r, c) => `Key byte k[${r},${c}]`,
    inspKeyRes: (a, k) => `XOR result (${a} ⊕ ${k})`,
    inspKeyNote: "<ul><li><strong>Why XOR instead of addition?</strong> XOR is its own inverse (<code>(A ⊕ K) ⊕ K = A</code>) and generates no carries, running in constant time without side-channel carry timing.</li></ul>",
    keyTabCols: ["Round", "Col 1", "Col 2", "Col 3", "Col 4", "16-byte round key"],
    keyRoundLbl: (r) => `Round ${r}`,
    keyInspTitle: (w) => `Derivation of Word W[${w}]`,
    keyInitBox: (i, w) => `<strong>W[${i}] = [${w}]</strong><br>The first 4 words (W[0]..W[3]) are copied directly from the initial 128-bit cipher key.`,
    keyRotBox: (i) => `<strong>Multiple-of-4 derivation:</strong> W[${i}] = W[${i - 4}] ⊕ SubWord(RotWord(W[${i - 1}])) ⊕ Rcon[${i / 4}]`,
    keyRotR1: (i) => `1. Previous word W[${i - 1}]`,
    keyRotR2: "2. RotWord (rotate left 1 byte)",
    keyRotR3: "3. SubWord (S-Box substitution)",
    keyRotR4: (r, rc) => `4. XOR with Rcon[${r}] (${rc} 00 00 00)`,
    keyRotR5: (i) => `5. Word W[${i - 4}]`,
    keyRotR6: (i) => `6. Result W[${i}] (Step 4 ⊕ Step 5)`,
    keyXorBox: (i) => `<strong>Standard derivation:</strong> W[${i}] = W[${i - 4}] ⊕ W[${i - 1}]`,
    keyXorR1: (i) => `Word W[${i - 4}]`,
    keyXorR2: (i) => `Word W[${i - 1}]`,
    keyXorR3: (i) => `XOR result W[${i}]`
  }
};

/* 5. UYGULAMA DURUMU VE GÖRSELLEŞTİRME / APP STATE & RENDERING */
const APP = {
  lang: "tr",
  tab: "prep",
  roundIdx: 1,
  stepKey: "afterSub",
  cellIdx: 0,
  wordIdx: 4,
  showDiff: true,
  presentMode: false,
  notesOpen: new Set(),
  pt1Str: "ARABA",
  pt2Str: "ARABB",
  pt1: [],
  pt2: [],
  keyData: null,
  enc1: [],
  enc2: [],
  dec1: []
};

function L() {
  return I18N[APP.lang] || I18N.tr;
}

function getStepLabel(step, isEnc) {
  const t = L();
  switch (step) {
    case "input": return t.stepInput;
    case "rk": return t.stepRk;
    case "afterSub": return isEnc ? t.stepSub : t.stepInvSub;
    case "afterShift": return isEnc ? t.stepShift : t.stepInvShift;
    case "afterMix": return isEnc ? t.stepMix : t.stepInvMix;
    case "afterKey": return t.stepKey;
    default: return step;
  }
}

function updateFieldHints() {
  const t = L();
  const updateBlockHint = (raw, elId) => {
    const s = raw.trim();
    const el = document.getElementById(elId);
    if (!el) return;
    if (/^[0-9a-fA-F]{32}$/.test(s)) {
      el.textContent = t.hintHexBlock;
      el.classList.remove("warn");
    } else if (s.length > 16) {
      el.textContent = t.hintTruncBlock(s.length);
      el.classList.add("warn");
    } else {
      el.textContent = t.hintAsciiBlock(s.length);
      el.classList.remove("warn");
    }
  };

  updateBlockHint(APP.pt1Str, "pt1-hint");
  updateBlockHint(APP.pt2Str, "pt2-hint");

  const pad = document.getElementById("pad-select").value;
  const padHint = document.getElementById("pad-hint");
  if (padHint) padHint.textContent = pad === "pkcs7" ? t.hintPadPkcs7 : t.hintPadZero;

  const keyRaw = document.getElementById("key-input").value.trim();
  const keyClean = keyRaw.replace(/[^0-9a-fA-F]/g, "");
  const keyHint = document.getElementById("key-hint");
  if (keyHint) {
    if (keyRaw !== keyClean && keyRaw.replace(/\s+/g, "") !== keyClean) {
      keyHint.textContent = t.hintKeyDirty(Math.min(keyClean.length, 32));
      keyHint.classList.add("warn");
    } else if (keyClean.length < 32) {
      keyHint.textContent = t.hintKeyShort(keyClean.length);
      keyHint.classList.add("warn");
    } else {
      keyHint.textContent = t.hintKeyOk;
      keyHint.classList.remove("warn");
    }
  }
}

function updateAll() {
  APP.pt1Str = document.getElementById("pt1-input").value || "ARABA";
  APP.pt2Str = document.getElementById("pt2-input").value || "ARABB";
  const pad = document.getElementById("pad-select").value;
  const keyBytes = parseKey(document.getElementById("key-input").value);

  APP.pt1 = parseBlock(APP.pt1Str, pad);
  APP.pt2 = parseBlock(APP.pt2Str, pad);
  APP.keyData = AES.expandKey(keyBytes);
  APP.enc1 = AES.encrypt(APP.pt1, APP.keyData.roundKeys);
  APP.enc2 = AES.encrypt(APP.pt2, APP.keyData.roundKeys);
  APP.dec1 = AES.decrypt(APP.enc1[10].afterKey, APP.keyData.roundKeys);

  updateFieldHints();
  document.getElementById("diff-toggle-text").innerHTML = L().diffToggle(escapeHtml(APP.pt2Str));
  renderBanner();
  renderRoundButtons();
  renderCurrentTab();
}

function renderBanner() {
  const t = L();
  const ct1 = APP.enc1[10].afterKey;
  const ct2 = APP.enc2[10].afterKey;
  const inDiff = countBitDiff(APP.pt1, APP.pt2);
  const outDiff = countBitDiff(ct1, ct2);

  const fmtDiffHex = (arr, ref) => arr.map((b, i) =>
    b !== ref[i] ? `<span class="hl-diff" title="${t.bannerInTitle}: ${hex2(ref[i])}">${hex2(b)}</span>` : hex2(b)
  ).join(" ");

  document.getElementById("diff-banner").innerHTML = `
    <div class="banner-box">
      <span class="banner-label">${t.bannerMain(escapeHtml(APP.pt1Str))}</span>
      <div class="banner-line"><span class="banner-key">${t.bannerIn}</span><span>${hexStr(APP.pt1)}</span></div>
      <div class="banner-line"><span class="banner-key">${t.bannerOut}</span><strong>${hexStr(ct1)}</strong></div>
    </div>
    <div class="banner-box">
      <span class="banner-label">${t.bannerCmp(escapeHtml(APP.pt2Str))}</span>
      <div class="banner-line"><span class="banner-key">${t.bannerIn}</span><span>${fmtDiffHex(APP.pt2, APP.pt1)}</span></div>
      <div class="banner-line"><span class="banner-key">${t.bannerOut}</span><strong>${fmtDiffHex(ct2, ct1)}</strong></div>
    </div>
    <div class="aval-stat">
      <div class="aval-row"><span>${t.avalIn}</span><strong>${t.fmtBytes(inDiff.bytes)} (${t.fmtBits(inDiff.bits)})</strong></div>
      <div class="aval-row aval-out"><span>${t.avalOut}</span><strong>${t.fmtBytes(outDiff.bytes)} · ${t.fmtBits(outDiff.bits)} (${t.fmtPct(((outDiff.bits / 128) * 100).toFixed(1))})</strong></div>
    </div>`;
}

function renderPrepTab() {
  const t = L();
  const pt1Label = escapeHtml(APP.pt1Str);
  const pt2Label = escapeHtml(APP.pt2Str);
  let rows = "";
  for (let i = 0; i < 16; i++) {
    const b1 = APP.pt1[i], b2 = APP.pt2[i];
    const ch1 = (b1 >= 32 && b1 <= 126) ? String.fromCharCode(b1) : t.padLbl;
    const ch2 = (b2 >= 32 && b2 <= 126) ? String.fromCharCode(b2) : t.padLbl;
    const isDiff = b1 !== b2;
    rows += `<tr class="${isDiff ? "diff-row" : ""}">
      <td>${t.byteWord} ${i + 1} (s[${i % 4},${Math.floor(i / 4)}])</td>
      <td>${escapeHtml(ch1)} → ${b1} → <strong>${hex2(b1)}</strong> (${bin8(b1)})</td>
      <td>${escapeHtml(ch2)} → ${b2} → <strong>${hex2(b2)}</strong> (${bin8(b2)})</td>
      <td>${isDiff ? t.bitDiffLbl(countBitDiff([b1], [b2]).bits) : t.sameLbl}</td>
    </tr>`;
  }

  let stateCells = "";
  for (let r = 0; r < 4; r++) {
    stateCells += "<tr>";
    for (let c = 0; c < 4; c++) {
      const idx = c * 4 + r;
      const b1 = APP.pt1[idx], b2 = APP.pt2[idx];
      stateCells += `<td class="${b1 !== b2 ? "diff-cell" : ""}">
        <span class="cell-meta">${idx + 1}. ${t.byteWord} · s[${r},${c}]</span>
        ${hex2(b1)}
        ${b1 !== b2 ? `<span class="diff-sub">≠ ${hex2(b2)}</span>` : ""}
      </td>`;
    }
    stateCells += "</tr>";
  }

  let avalRows = "";
  for (let r = 0; r <= 10; r++) {
    const d = countBitDiff(APP.enc1[r].afterKey, APP.enc2[r].afterKey);
    avalRows += `<tr>
      <td>${r === 0 ? t.stageStart : t.stageEnd(r)}</td>
      <td>${d.bytes} / 16 ${t.unitByte}</td>
      <td><strong>${d.bits} / 128 ${APP.lang === "en" ? "bits" : "bit"} (${t.fmtPct(((d.bits / 128) * 100).toFixed(1))})</strong></td>
    </tr>`;
  }

  document.getElementById("prep-content").innerHTML = `
    <div class="card">
      <div class="card-head"><h2>${t.prepAsciiHead(pt1Label, pt2Label)}</h2></div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>${t.colPos}</th><th>${t.colAscii(pt1Label)}</th><th>${pt2Label}</th><th>${t.colDiff}</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
    <div class="prep-right-stack">
      <div class="card">
        <div class="card-head">
          <h2>${t.prepStateTitle}</h2>
          <span class="muted-note">${t.prepStateBadge}</span>
        </div>
        <p class="muted-note card-subtitle">${t.prepStateSub}</p>
        <div class="table-scroll"><table class="state-table"><tbody>${stateCells}</tbody></table></div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2>${t.prepAvalTitle}</h2>
          <span class="muted-note">${t.prepAvalBadge}</span>
        </div>
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>${t.colStage}</th><th>${t.colChangedBytes}</th><th>${t.colChangedBits}</th></tr></thead>
            <tbody>${avalRows}</tbody>
          </table>
        </div>
      </div>
    </div>`;
}

function renderRoundButtons() {
  const t = L();
  const ctrl = document.getElementById("round-controls");
  const isRoundTab = APP.tab === "enc" || APP.tab === "dec";
  ctrl.classList.toggle("visible", isRoundTab);
  if (!isRoundTab) return;

  let html = "";
  for (let i = 0; i <= 10; i++) {
    const lbl = APP.tab === "enc"
      ? (i === 0 ? t.rndEnc0 : t.rndEncN(i))
      : (i === 0 ? t.rndDec0 : t.rndDecN(i));
    html += `<button type="button" class="${APP.roundIdx === i ? "active" : ""}" data-r="${i}">${lbl}</button>`;
  }
  const box = document.getElementById("round-buttons");
  box.innerHTML = html;
  box.querySelectorAll("button").forEach(b => {
    b.addEventListener("click", () => {
      APP.roundIdx = parseInt(b.dataset.r, 10);
      APP.stepKey = APP.roundIdx === 0 ? "afterKey" : "afterSub";
      renderRoundButtons();
      renderRoundsTab();
    });
  });
}

function buildStateCard(title, desc, bytes, refBytes, stepKey) {
  let rows = "";
  for (let r = 0; r < 4; r++) {
    rows += "<tr>";
    for (let c = 0; c < 4; c++) {
      const idx = c * 4 + r;
      const isSel = APP.stepKey === stepKey && APP.cellIdx === idx;
      const hasDiff = APP.showDiff && APP.tab === "enc" && refBytes && bytes[idx] !== refBytes[idx];
      const valHex = hex2(bytes[idx]);
      const diffTxt = hasDiff ? `, ≠ ${hex2(refBytes[idx])}` : "";
      rows += `<td tabindex="0" role="button" aria-pressed="${isSel}" aria-label="${title} s[${r},${c}]: ${valHex}${diffTxt}" class="${isSel ? "selected" : ""} ${hasDiff ? "diff-cell" : ""}" data-step="${stepKey}" data-idx="${idx}">
        <span class="cell-meta">s[${r},${c}]</span>
        ${valHex}
        ${hasDiff ? `<span class="diff-sub">≠ ${hex2(refBytes[idx])}</span>` : ""}
      </td>`;
    }
    rows += "</tr>";
  }
  return `<div class="matrix-card">
    <h3>${title}</h3>
    <div class="step-desc">${desc}</div>
    <table class="state-table"><tbody>${rows}</tbody></table>
  </div>`;
}

function renderRoundsTab() {
  const t = L();
  const isEnc = APP.tab === "enc";
  const r1 = isEnc ? APP.enc1[APP.roundIdx] : APP.dec1[APP.roundIdx];
  const r2 = isEnc ? APP.enc2[APP.roundIdx] : null;

  const guide = document.getElementById("round-guide");
  const roundNote = document.getElementById("round-note-body");

  if (APP.roundIdx === 0) {
    guide.innerHTML = isEnc ? t.guideEnc0 : t.guideDec0;
    roundNote.innerHTML = isEnc ? t.noteEnc0 : t.noteDec0;
  } else if (isEnc) {
    guide.innerHTML = t.guideEncN(r1.round, Boolean(r1.afterMix));
    roundNote.innerHTML = r1.afterMix ? t.noteEncMix : t.noteEncLast;
  } else {
    guide.innerHTML = t.guideDecN(r1.round, Boolean(r1.afterMix));
    roundNote.innerHTML = t.noteDecN;
  }

  const cards = [];
  if (APP.roundIdx === 0) {
    cards.push(buildStateCard(t.c0InTitle, t.c0InDesc, r1.input, r2 && r2.input, "input"));
    cards.push(buildStateCard(t.c0RkTitle, isEnc ? t.c0RkEnc : t.c0RkDec, r1.rk, r2 && r2.rk, "rk"));
    cards.push(buildStateCard(t.c0KeyTitle, t.c0KeyDesc, r1.afterKey, r2 && r2.afterKey, "afterKey"));
  } else if (isEnc) {
    cards.push(buildStateCard(t.cEncInTitle, t.cEncInDesc(r1.round - 1), r1.input, r2.input, "input"));
    cards.push(buildStateCard(t.cEncSubTitle, t.cEncSubDesc, r1.afterSub, r2.afterSub, "afterSub"));
    cards.push(buildStateCard(t.cEncShiftTitle, t.cEncShiftDesc, r1.afterShift, r2.afterShift, "afterShift"));
    if (r1.afterMix) cards.push(buildStateCard(t.cEncMixTitle, t.cEncMixDesc, r1.afterMix, r2.afterMix, "afterMix"));
    cards.push(buildStateCard(t.cEncKeyTitle(Boolean(r1.afterMix)), t.cEncKeyDesc(r1.round), r1.afterKey, r2.afterKey, "afterKey"));
  } else {
    cards.push(buildStateCard(t.cDecInTitle, t.cDecInDesc, r1.input, null, "input"));
    cards.push(buildStateCard(t.cDecShiftTitle, t.cDecShiftDesc, r1.afterShift, null, "afterShift"));
    cards.push(buildStateCard(t.cDecSubTitle, t.cDecSubDesc, r1.afterSub, null, "afterSub"));
    cards.push(buildStateCard(t.cDecKeyTitle, t.cDecKeyDesc(r1.round), r1.afterKey, null, "afterKey"));
    if (r1.afterMix) cards.push(buildStateCard(t.cDecMixTitle, t.cDecMixDesc, r1.afterMix, null, "afterMix"));
  }

  const grid = document.getElementById("matrices-grid");
  grid.innerHTML = cards.join("");
  const selectCell = td => {
    APP.stepKey = td.dataset.step;
    APP.cellIdx = parseInt(td.dataset.idx, 10);
    renderRoundsTab();
  };
  grid.querySelectorAll("td[data-step]").forEach(td => {
    td.addEventListener("click", () => selectCell(td));
    td.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        selectCell(td);
      }
    });
  });

  renderInspector(r1, isEnc);
}

function renderInspector(rData, isEnc) {
  const t = L();
  const idx = APP.cellIdx, r = idx % 4, c = Math.floor(idx / 4), step = APP.stepKey;
  const stepLabel = getStepLabel(step, isEnc);
  document.getElementById("insp-coord").textContent = t.inspCoord(r, c, idx + 1, stepLabel);
  const box = document.getElementById("insp-content");
  const noteBox = document.getElementById("insp-note-body");
  let sboxHl = null;

  if (step === "afterSub") {
    const inB = isEnc ? rData.input[idx] : rData.afterShift[idx];
    const outB = rData.afterSub[idx];
    const inv = GF.inv(inB);
    sboxHl = { byte: inB, inv: !isEnc };
    box.innerHTML = `
      <div class="formula-box">
        ${t.inspSubBox(hex2(inB), isEnc ? "S-Box" : "InvS-Box", hex2(inB)[0], hex2(inB)[1], hex2(outB))}
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>${t.inspSubHead}</th><th>Hex</th><th>${t.inspBinCol}</th></tr></thead>
          <tbody>
            <tr><td>${t.inspSubR1}</td><td>${hex2(inB)}</td><td>${bin8(inB)}</td></tr>
            <tr><td>${t.inspSubR2}</td><td>${hex2(inv)}</td><td>${bin8(inv)}</td></tr>
            <tr><td>${t.inspSubR3}</td><td><strong>${hex2(outB)}</strong></td><td><strong>${bin8(outB)}</strong></td></tr>
          </tbody>
        </table>
      </div>`;
    noteBox.innerHTML = t.inspSubNote;
  } else if (step === "afterShift") {
    const srcCol = isEnc ? (c + r) % 4 : (c - r + 4) % 4;
    const val = rData.afterShift[idx];
    box.innerHTML = `
      <div class="formula-box">
        ${t.inspShiftBox(r + 1, r, isEnc ? t.dirLeft : t.dirRight, srcCol, hex2(val), c)}
      </div>`;
    noteBox.innerHTML = t.inspShiftNote;
  } else if (step === "afterMix" && rData.afterMix) {
    const src = isEnc ? rData.afterShift : rData.afterKey;
    const col = src.slice(c * 4, c * 4 + 4);
    const M = isEnc
      ? [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
      : [[0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d], [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]];
    const cf = M[r];
    const outVal = rData.afterMix[idx];

    const rows = [0, 1, 2, 3].map(i => {
      const b = col[i], k = cf[i], p = GF.mul(k, b);
      const msb = (b & 0x80) !== 0, sh = (b << 1) & 0xff;
      let exp = "";
      if (k === 1) exp = t.mixUnit(hex2(b));
      else if (k === 2) exp = t.mixDouble(hex2(sh), msb, hex2(p));
      else if (k === 3) exp = t.mixTriple(hex2(b), hex2(GF.mul(2, b)), hex2(p));
      else exp = t.mixPoly(hex2(k), hex2(b), hex2(p));
      return `<tr><td class="nowrap">${hex2(k)} • ${hex2(b)}</td><td>${exp}</td><td><strong>${hex2(p)}</strong></td><td>${bin8(p)}</td></tr>`;
    }).join("");

    box.innerHTML = `
      <div class="formula-box">
        <strong>${t.mixEqTitle(c)}</strong>
        (${hex2(cf[0])}•${hex2(col[0])}) ⊕ (${hex2(cf[1])}•${hex2(col[1])}) ⊕ (${hex2(cf[2])}•${hex2(col[2])}) ⊕ (${hex2(cf[3])}•${hex2(col[3])}) = <strong>${hex2(outVal)}</strong>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>${t.mixColMul}</th><th>${t.mixColStep}</th><th>Hex</th><th>${t.inspBinCol}</th></tr></thead>
          <tbody>
            ${rows}
            <tr><th colspan="2">${t.mixSum}</th><th>${hex2(outVal)}</th><th>${bin8(outVal)}</th></tr>
          </tbody>
        </table>
      </div>`;
    noteBox.innerHTML = t.inspMixNote;
  } else {
    const pre = APP.roundIdx === 0 ? rData.input : (isEnc ? (rData.afterMix || rData.afterShift) : rData.afterSub);
    const a = pre[idx], k = rData.rk[idx], res = rData.afterKey[idx];
    box.innerHTML = `
      <div class="formula-box">${t.inspKeyBox}</div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>${t.colVal}</th><th>Hex</th><th>${t.inspBinCol}</th></tr></thead>
          <tbody>
            <tr><td>${t.inspKeyR1(r, c)}</td><td>${hex2(a)}</td><td>${bin8(a)}</td></tr>
            <tr><td>${t.inspKeyR2(r, c)}</td><td>${hex2(k)}</td><td>${bin8(k)}</td></tr>
            <tr><th>${t.inspKeyRes(hex2(a), hex2(k))}</th><th>${hex2(res)}</th><th>${bin8(res)}</th></tr>
          </tbody>
        </table>
      </div>`;
    noteBox.innerHTML = t.inspKeyNote;
  }

  renderSBox(sboxHl);
}

function renderSBox(hl) {
  const t = L();
  const isInv = hl ? hl.inv : (APP.tab === "dec");
  const tbl = isInv ? TABLES.invSbox : TABLES.sbox;
  const hitR = hl ? (hl.byte >> 4) : -1, hitC = hl ? (hl.byte & 0x0f) : -1;

  document.getElementById("sbox-title").textContent = isInv ? t.invSboxTitle : t.sboxTitle;

  let h = `<table class="sbox-table"><thead><tr><th></th>`;
  for (let c = 0; c < 16; c++) h += `<th>${c.toString(16).toUpperCase()}</th>`;
  h += `</tr></thead><tbody>`;
  for (let r = 0; r < 16; r++) {
    h += `<tr><th>${r.toString(16).toUpperCase()}</th>`;
    for (let c = 0; c < 16; c++) {
      const cls = (r === hitR && c === hitC) ? "hit" : (r === hitR || c === hitC ? "rc-hl" : "");
      h += `<td class="${cls}">${hex2(tbl[r * 16 + c])}</td>`;
    }
    h += `</tr>`;
  }
  h += `</tbody></table>`;
  document.getElementById("sbox-grid").innerHTML = h;
}

function renderKeyTab() {
  const t = L();
  const { W, logs, roundKeys } = APP.keyData;
  let rows = "";
  for (let r = 0; r <= 10; r++) {
    rows += `<tr><th class="nowrap">${t.keyRoundLbl(r)}</th>`;
    for (let c = 0; c < 4; c++) {
      const wi = r * 4 + c;
      rows += `<td><button type="button" class="w-btn ${APP.wordIdx === wi ? "active" : ""}" data-w="${wi}">W[${wi}]: ${W[wi].map(hex2).join("")}</button></td>`;
    }
    rows += `<td><span class="key-hex-line">${hexStr(roundKeys[r])}</span></td></tr>`;
  }
  const container = document.getElementById("key-schedule-table");
  container.innerHTML = `<table class="data-table"><thead><tr>${t.keyTabCols.map(h => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>`;

  container.querySelectorAll(".w-btn").forEach(b => {
    b.addEventListener("click", () => {
      APP.wordIdx = parseInt(b.dataset.w, 10);
      renderKeyTab();
    });
  });

  const lg = logs[APP.wordIdx];
  const out = document.getElementById("key-insp-content");
  document.getElementById("key-insp-title").textContent = t.keyInspTitle(APP.wordIdx);

  if (lg.type === "init") {
    out.innerHTML = `<div class="formula-box">${t.keyInitBox(lg.i, hexStr(lg.word))}</div>`;
  } else if (lg.type === "rot") {
    out.innerHTML = `
      <div class="formula-box">${t.keyRotBox(lg.i)}</div>
      <div class="table-scroll">
        <table class="data-table">
          <tbody>
            <tr><th>${t.keyRotR1(lg.i)}</th><td>${hexStr(lg.prev)}</td></tr>
            <tr><th>${t.keyRotR2}</th><td>${hexStr(lg.rot)}</td></tr>
            <tr><th>${t.keyRotR3}</th><td>${hexStr(lg.sub)}</td></tr>
            <tr><th>${t.keyRotR4(lg.i / 4, hex2(lg.rc))}</th><td>${hexStr(lg.rconXor)}</td></tr>
            <tr><th>${t.keyRotR5(lg.i)}</th><td>${hexStr(lg.prev4)}</td></tr>
            <tr><th>${t.keyRotR6(lg.i)}</th><td><strong>${hexStr(lg.word)}</strong></td></tr>
          </tbody>
        </table>
      </div>`;
  } else {
    out.innerHTML = `
      <div class="formula-box">${t.keyXorBox(lg.i)}</div>
      <div class="table-scroll">
        <table class="data-table">
          <tbody>
            <tr><th>${t.keyXorR1(lg.i)}</th><td>${hexStr(lg.prev4)}</td></tr>
            <tr><th>${t.keyXorR2(lg.i)}</th><td>${hexStr(lg.prev)}</td></tr>
            <tr><th>${t.keyXorR3(lg.i)}</th><td><strong>${hexStr(lg.word)}</strong></td></tr>
          </tbody>
        </table>
      </div>`;
  }
}

function syncPresenterNotes() {
  const t = L();
  document.querySelectorAll(".presenter-note[data-note-id]").forEach(det => {
    const want = APP.notesOpen.has(det.dataset.noteId);
    if (det.open !== want) det.open = want;
  });
  const btn = document.getElementById("toggle-notes-btn");
  if (btn) {
    const activeNotes = Array.from(document.querySelectorAll(".tab-panel.active .presenter-note[data-note-id]"));
    const anyClosed = activeNotes.some(d => !APP.notesOpen.has(d.dataset.noteId));
    btn.textContent = anyClosed ? t.notesOpenAll : t.notesCloseAll;
  }
}

function toggleActiveTabNotes() {
  const activeNotes = Array.from(document.querySelectorAll(".tab-panel.active .presenter-note[data-note-id]"));
  const shouldOpen = activeNotes.some(d => !APP.notesOpen.has(d.dataset.noteId));
  activeNotes.forEach(d => {
    if (shouldOpen) APP.notesOpen.add(d.dataset.noteId);
    else APP.notesOpen.delete(d.dataset.noteId);
  });
  syncPresenterNotes();
}

function renderCurrentTab() {
  document.getElementById("tab-prep").classList.toggle("active", APP.tab === "prep");
  document.getElementById("tab-rounds").classList.toggle("active", APP.tab === "enc" || APP.tab === "dec");
  document.getElementById("tab-key").classList.toggle("active", APP.tab === "key");

  if (APP.tab === "prep") renderPrepTab();
  else if (APP.tab === "enc" || APP.tab === "dec") renderRoundsTab();
  else if (APP.tab === "key") renderKeyTab();

  syncPresenterNotes();
}

function switchTab(tabName) {
  document.querySelectorAll(".tab-btn").forEach(b => {
    const isAct = b.dataset.tab === tabName;
    b.classList.toggle("active", isAct);
    b.setAttribute("aria-selected", String(isAct));
  });
  const roundsPanel = document.getElementById("tab-rounds");
  if (roundsPanel) {
    roundsPanel.setAttribute("aria-labelledby", tabName === "dec" ? "tab-btn-dec" : "tab-btn-enc");
  }
  APP.tab = tabName;
  APP.roundIdx = 1;
  APP.stepKey = "afterSub";
  renderRoundButtons();
  renderCurrentTab();
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("aes_theme", theme);
  const t = L();
  const label = document.getElementById("theme-btn-label");
  if (label) label.textContent = theme === "dark" ? t.themeLight : t.themeDark;
  const btn = document.getElementById("theme-btn");
  if (btn) btn.setAttribute("aria-pressed", String(theme === "light"));
}

function applyPresentMode(on) {
  APP.presentMode = on;
  document.documentElement.setAttribute("data-present", on ? "true" : "false");
  localStorage.setItem("aes_present", on ? "true" : "false");
  const btn = document.getElementById("present-btn");
  if (btn) btn.setAttribute("aria-pressed", String(on));
}

function applyLanguage(lang, rerender = true) {
  APP.lang = lang === "en" ? "en" : "tr";
  localStorage.setItem("aes_lang", APP.lang);
  document.documentElement.lang = APP.lang;
  const t = L();
  document.title = t.pageTitle;

  document.querySelectorAll(".lang-btn").forEach(b => {
    const active = b.dataset.lang === APP.lang;
    b.classList.toggle("active", active);
    b.setAttribute("aria-pressed", String(active));
  });

  const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  const setHtml = (id, val) => { const el = document.getElementById(id); if (el) el.innerHTML = val; };

  setText("skip-link", t.skipLink);
  setText("app-title", t.appTitle);
  setText("slides-link", t.slidesLink);
  const slidesLink = document.getElementById("slides-link");
  if (slidesLink) slidesLink.href = `sunum.html?lang=${APP.lang}`;

  setText("present-btn-label", t.presentBtn);
  const curTheme = document.documentElement.getAttribute("data-theme") || "dark";
  setText("theme-btn-label", curTheme === "dark" ? t.themeLight : t.themeDark);

  setText("lbl-pt1", t.lblPt1);
  setText("lbl-pt2", t.lblPt2);
  setText("lbl-pad", t.lblPad);
  setText("opt-pad-zero", t.optZero);
  setText("opt-pad-pkcs7", t.optPkcs7);
  setText("lbl-key", t.lblKey);

  const nav = document.getElementById("main-nav");
  if (nav) nav.setAttribute("aria-label", t.navAria);
  setText("tab-btn-prep", t.tabPrep);
  setText("tab-btn-enc", t.tabEnc);
  setText("tab-btn-key", t.tabKey);
  setText("tab-btn-dec", t.tabDec);

  setText("kh-tabs", t.khTabs);
  setText("kh-step", t.khStep);
  setText("kh-notes", t.khNotes);
  setText("kh-theme", t.khTheme);

  document.querySelectorAll(".note-title").forEach(el => { el.textContent = t.noteTitle; });
  setText("prep-note-meta", t.prepNoteMeta);
  setText("round-note-meta", t.roundNoteMeta);
  setText("insp-note-meta", t.inspNoteMeta);
  setText("key-note-meta", t.keyNoteMeta);

  setHtml("prep-guide", t.prepGuide);
  setHtml("prep-note-body", t.prepNotes);
  setHtml("key-guide", t.keyGuide);
  setHtml("key-note-body", t.keyNotes);

  setText("insp-title", t.inspTitle);
  setText("sbox-hint", t.sboxHint);
  setText("key-table-title", t.keyTableTitle);
  setText("key-table-hint", t.keyTableHint);

  if (rerender && APP.pt1.length) {
    updateFieldHints();
    setHtml("diff-toggle-text", t.diffToggle(escapeHtml(APP.pt2Str)));
    renderBanner();
    renderRoundButtons();
    renderCurrentTab();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const qLang = params.get("lang");
  const initLang = (qLang === "en" || qLang === "tr") ? qLang : (localStorage.getItem("aes_lang") || "tr");
  applyLanguage(initLang, false);

  const qTheme = params.get("theme");
  const savedTheme = (qTheme === "light" || qTheme === "dark") ? qTheme : (localStorage.getItem("aes_theme") || "dark");
  applyTheme(savedTheme);
  applyPresentMode(params.get("present") === "1" || localStorage.getItem("aes_present") === "true");

  document.querySelectorAll(".lang-btn").forEach(btn => {
    btn.addEventListener("click", () => applyLanguage(btn.dataset.lang, true));
  });

  document.getElementById("theme-btn").addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme");
    applyTheme(cur === "dark" ? "light" : "dark");
  });

  document.getElementById("present-btn").addEventListener("click", () => {
    applyPresentMode(!APP.presentMode);
  });

  document.getElementById("toggle-notes-btn").addEventListener("click", toggleActiveTabNotes);

  document.querySelectorAll(".presenter-note[data-note-id]").forEach(det => {
    det.addEventListener("toggle", () => {
      const id = det.dataset.noteId;
      if (det.open) APP.notesOpen.add(id);
      else APP.notesOpen.delete(id);
      syncPresenterNotes();
    });
  });

  ["pt1-input", "pt2-input", "key-input"].forEach(id => {
    document.getElementById(id).addEventListener("input", updateAll);
  });
  document.getElementById("pad-select").addEventListener("change", updateAll);
  document.getElementById("show-diff-chk").addEventListener("change", e => {
    APP.showDiff = e.target.checked;
    renderRoundsTab();
  });

  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  document.addEventListener("keydown", e => {
    const tag = e.target && e.target.tagName;
    if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    if (e.key === "1") switchTab("prep");
    else if (e.key === "2") switchTab("enc");
    else if (e.key === "3") switchTab("key");
    else if (e.key === "4") switchTab("dec");
    else if (e.key === "t" || e.key === "T") {
      const cur = document.documentElement.getAttribute("data-theme");
      applyTheme(cur === "dark" ? "light" : "dark");
    } else if (e.key === "p" || e.key === "P") {
      applyPresentMode(!APP.presentMode);
    } else if (e.key === "n" || e.key === "N") {
      toggleActiveTabNotes();
    } else if (e.key === "ArrowRight") {
      if (APP.tab === "enc" || APP.tab === "dec") {
        if (APP.roundIdx < 10) {
          APP.roundIdx++;
          APP.stepKey = APP.roundIdx === 0 ? "afterKey" : "afterSub";
          renderRoundButtons();
          renderRoundsTab();
        }
      } else if (APP.tab === "key" && APP.wordIdx < 43) {
        APP.wordIdx++;
        renderKeyTab();
      }
    } else if (e.key === "ArrowLeft") {
      if (APP.tab === "enc" || APP.tab === "dec") {
        if (APP.roundIdx > 0) {
          APP.roundIdx--;
          APP.stepKey = APP.roundIdx === 0 ? "afterKey" : "afterSub";
          renderRoundButtons();
          renderRoundsTab();
        }
      } else if (APP.tab === "key" && APP.wordIdx > 0) {
        APP.wordIdx--;
        renderKeyTab();
      }
    }
  });

  updateAll();

  const qTab = params.get("tab");
  if (qTab && ["prep", "enc", "key", "dec"].includes(qTab)) {
    switchTab(qTab);
    const qRound = parseInt(params.get("round"), 10);
    if (!Number.isNaN(qRound) && qRound >= 0 && qRound <= 10 && (qTab === "enc" || qTab === "dec")) {
      APP.roundIdx = qRound;
      APP.stepKey = qRound === 0 ? "afterKey" : "afterSub";
      renderRoundButtons();
      renderRoundsTab();
    }
  }
});
