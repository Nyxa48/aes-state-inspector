"use strict";

/* 1. GF(2^8) SONLU CİSİM ARİTMETİĞİ VE TABLO ÜRETİMİ */
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

/* 2. AES-128 MOTORU */
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

/* 3. FORMAT YARDIMCILARI */
const hex2 = b => b.toString(16).toUpperCase().padStart(2, "0");
const bin8 = b => b.toString(2).padStart(8, "0");
const hexStr = arr => arr.map(hex2).join(" ");

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

/* 4. UYGULAMA DURUMU VE GÖRSELLEŞTİRME */
const APP = {
  tab: "prep",
  roundIdx: 1,
  stepKey: "afterSub",
  cellIdx: 0,
  wordIdx: 4,
  showDiff: true,
  pt1Str: "ARABA",
  pt2Str: "ARABB",
  pt1: [],
  pt2: [],
  keyData: null,
  enc1: [],
  enc2: [],
  dec1: []
};

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

  document.getElementById("diff-label-name").textContent = APP.pt2Str;
  renderBanner();
  renderRoundButtons();
  renderCurrentTab();
}

function renderBanner() {
  const ct1 = APP.enc1[10].afterKey;
  const ct2 = APP.enc2[10].afterKey;
  const inDiff = countBitDiff(APP.pt1, APP.pt2);
  const outDiff = countBitDiff(ct1, ct2);

  const fmtDiffHex = (arr, ref) => arr.map((b, i) =>
    b !== ref[i] ? `<span class="hl-diff" title="Ana metinde: ${hex2(ref[i])}">${hex2(b)}</span>` : hex2(b)
  ).join(" ");

  document.getElementById("diff-banner").innerHTML = `
    <div class="banner-box">
      <span class="banner-label">1. ANA METİN (${APP.pt1Str}) &rarr; GİRİŞ VE 10. TUR ŞİFRELİ ÇIKTI:</span>
      <div>Giriş : ${hexStr(APP.pt1)}</div>
      <div>Çıktı : <strong>${hexStr(ct1)}</strong></div>
    </div>
    <div class="banner-box">
      <span class="banner-label">2. KARŞILAŞTIRMA (${APP.pt2Str}) &rarr; FARKLI BAYTLAR KIRMIZI:</span>
      <div>Giriş : ${fmtDiffHex(APP.pt2, APP.pt1)}</div>
      <div>Çıktı : <strong>${fmtDiffHex(ct2, ct1)}</strong></div>
    </div>
    <div class="aval-stat">
      <div>Giriş Farkı: <strong>${inDiff.bytes} Bayt (${inDiff.bits} / 128 Bit)</strong></div>
      <div>Çıktı Farkı: <strong>${outDiff.bytes} Bayt (${outDiff.bits} / 128 Bit - %${((outDiff.bits / 128) * 100).toFixed(1)})</strong></div>
    </div>`;
}

function renderPrepTab() {
  let rows = "";
  for (let i = 0; i < 16; i++) {
    const b1 = APP.pt1[i], b2 = APP.pt2[i];
    const ch1 = (b1 >= 32 && b1 <= 126) ? String.fromCharCode(b1) : "(Dolgu 00)";
    const ch2 = (b2 >= 32 && b2 <= 126) ? String.fromCharCode(b2) : "(Dolgu 00)";
    const isDiff = b1 !== b2;
    rows += `<tr style="${isDiff ? "background:#fee2e2;font-weight:700;" : ""}">
      <td>Bayt ${i + 1} (s[${i % 4},${Math.floor(i / 4)}])</td>
      <td>${ch1} &rarr; ${ b1 } &rarr; <strong>${hex2(b1)}</strong> (${bin8(b1)})</td>
      <td>${ch2} &rarr; ${ b2 } &rarr; <strong>${hex2(b2)}</strong> (${bin8(b2)})</td>
      <td>${isDiff ? `${countBitDiff([b1], [b2]).bits} bit farklı` : "Aynı"}</td>
    </tr>`;
  }

  let stateCells = "";
  for (let r = 0; r < 4; r++) {
    stateCells += "<tr>";
    for (let c = 0; c < 4; c++) {
      const idx = c * 4 + r;
      const b1 = APP.pt1[idx], b2 = APP.pt2[idx];
      stateCells += `<td class="${b1 !== b2 ? "diff-cell" : ""}">
        <span class="cell-meta">${idx + 1}. Bayt (s[${r},${c}])</span>
        ${hex2(b1)}
        ${b1 !== b2 ? `<span class="diff-sub">${APP.pt2Str}: ${hex2(b2)}</span>` : ""}
      </td>`;
    }
    stateCells += "</tr>";
  }

  let avalRows = "";
  for (let r = 0; r <= 10; r++) {
    const d = countBitDiff(APP.enc1[r].afterKey, APP.enc2[r].afterKey);
    avalRows += `<tr>
      <td>${r === 0 ? "Başlangıç (Tur 0)" : `Tur ${r} Sonu`}</td>
      <td>${d.bytes} / 16 Bayt</td>
      <td><strong>${d.bits} / 128 Bit (%${((d.bits / 128) * 100).toFixed(1)})</strong></td>
    </tr>`;
  }

  document.getElementById("prep-content").innerHTML = `
    <div class="card">
      <div class="card-head"><h2>1. Harften Sayıya Dönüşüm (${APP.pt1Str} vs ${APP.pt2Str})</h2></div>
      <table class="data-table">
        <thead><tr><th>Konum</th><th>${APP.pt1Str} (ASCII &rarr; 10'luk &rarr; Hex)</th><th>${APP.pt2Str} Karşılaştırma</th><th>Fark</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div class="card">
      <div class="card-head"><h2>2. 4x4 Durum (State) Tablosu — Sütun Sütun Dizilim</h2></div>
      <p style="font-size:12px;color:#475569;margin-bottom:8px;">Dikkat: 1, 2, 3 ve 4. baytlar ilk satıra değil, ilk sütuna yukarıdan aşağıya yazılır.</p>
      <table class="state-table" style="margin-bottom:16px;"><tbody>${stateCells}</tbody></table>
      <div class="card-head"><h2>3. Tur Bazlı Çığ Etkisi (Farkın Yayılma Hızı)</h2></div>
      <table class="data-table">
        <thead><tr><th>Aşama</th><th>Değişen Bayt Sayısı</th><th>Değişen Bit Oranı</th></tr></thead>
        <tbody>${avalRows}</tbody>
      </table>
    </div>`;
}

function renderRoundButtons() {
  const ctrl = document.getElementById("round-controls");
  const isRoundTab = APP.tab === "enc" || APP.tab === "dec";
  ctrl.classList.toggle("visible", isRoundTab);
  if (!isRoundTab) return;

  let html = "";
  for (let i = 0; i <= 10; i++) {
    const lbl = APP.tab === "enc"
      ? (i === 0 ? "Başlangıç (Tur 0)" : `Tur ${i}`)
      : (i === 0 ? "Başlangıç (Tur 10 Anahtarı)" : `Ters Adım ${i} (Tur ${10 - i})`);
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
      rows += `<td class="${isSel ? "selected" : ""} ${hasDiff ? "diff-cell" : ""}" data-step="${stepKey}" data-idx="${idx}">
        <span class="cell-meta">s[${r},${c}]</span>
        ${hex2(bytes[idx])}
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
  const isEnc = APP.tab === "enc";
  const r1 = isEnc ? APP.enc1[APP.roundIdx] : APP.dec1[APP.roundIdx];
  const r2 = isEnc ? APP.enc2[APP.roundIdx] : null;

  const guide = document.getElementById("round-guide");
  if (APP.roundIdx === 0) {
    guide.innerHTML = isEnc
      ? `<strong>Başlangıç Adımı (Tur 0):</strong> Düz metin tablosu ile gizli anahtar üst üste konur ve her bayt karşılıklı XOR işlemine sokulur (AddRoundKey). Henüz S-Box veya kaydırma yoktur.`
      : `<strong>Deşifreleme Başlangıcı:</strong> Şifreli metin, 10. turun anahtarıyla XOR'lanarak geri açma işlemine başlanır.`;
  } else if (isEnc) {
    guide.innerHTML = `<strong>Tur ${r1.round} Akışı:</strong> 1. <strong>SubBytes</strong> (Tablodan harf değiştir - Karışıklık/Confusion) &rarr; 2. <strong>ShiftRows</strong> (Satırları sola kaydır) &rarr; ${r1.afterMix ? "3. <strong>MixColumns</strong> (Sütunları matrisle çarpıp yay - Yayılma/Diffusion) &rarr; 4." : "3. (Son turda MixColumns yapılmaz)"} <strong>AddRoundKey</strong> (Tur ${r1.round} anahtarıyla XOR'la).`;
  } else {
    guide.innerHTML = `<strong>Ters Adım (Tur ${r1.round}'a Dönüş):</strong> Şifreleme adımları tam ters sırayla uygulanır: <strong>InvShiftRows</strong> (Sağa kaydır) &rarr; <strong>InvSubBytes</strong> (Ters S-Box) &rarr; <strong>AddRoundKey</strong> (XOR'un tersi yine kendisidir) ${r1.afterMix ? "&rarr; <strong>InvMixColumns</strong> (0E, 0B, 0D, 09 ters matrisiyle çarp)" : ""}.`;
  }

  const cards = [];
  if (APP.roundIdx === 0) {
    cards.push(buildStateCard("1. Giriş Tablosu", "İşleme giren 16 baytlık durum", r1.input, r2 && r2.input, "input"));
    cards.push(buildStateCard("2. Tur Anahtarı", isEnc ? "Başlangıç Anahtarı (Key 0)" : "Tur 10 Anahtarı", r1.rk, r2 && r2.rk, "rk"));
    cards.push(buildStateCard("3. AddRoundKey Sonucu", "Giriş ⊕ Anahtar (Bayt bayt XOR)", r1.afterKey, r2 && r2.afterKey, "afterKey"));
  } else if (isEnc) {
    cards.push(buildStateCard("0. Tur Girişi", `Tur ${r1.round - 1} sonundaki tablo`, r1.input, r2.input, "input"));
    cards.push(buildStateCard("1. SubBytes", "Her bayt S-Box tablosundan değiştirilir", r1.afterSub, r2.afterSub, "afterSub"));
    cards.push(buildStateCard("2. ShiftRows", "Satırlar 0, 1, 2, 3 kutu sola kayar", r1.afterShift, r2.afterShift, "afterShift"));
    if (r1.afterMix) cards.push(buildStateCard("3. MixColumns", "Sütundaki 4 bayt birbiriyle karıştırılır", r1.afterMix, r2.afterMix, "afterMix"));
    cards.push(buildStateCard(r1.afterMix ? "4. AddRoundKey" : "3. AddRoundKey (Son Tur)", `Tur ${r1.round} anahtarıyla XOR mühürleme`, r1.afterKey, r2.afterKey, "afterKey"));
  } else {
    cards.push(buildStateCard("0. Giriş", "Önceki adımdan gelen tablo", r1.input, null, "input"));
    cards.push(buildStateCard("1. InvShiftRows", "Satırlar 0, 1, 2, 3 kutu sağa kayar", r1.afterShift, null, "afterShift"));
    cards.push(buildStateCard("2. InvSubBytes", "Ters S-Box tablosundan geri çevrilir", r1.afterSub, null, "afterSub"));
    cards.push(buildStateCard("3. AddRoundKey", `Tur ${r1.round} anahtarıyla XOR`, r1.afterKey, null, "afterKey"));
    if (r1.afterMix) cards.push(buildStateCard("4. InvMixColumns", "Ters matris (0E,0B,0D,09) çarpımı", r1.afterMix, null, "afterMix"));
  }

  const grid = document.getElementById("matrices-grid");
  grid.innerHTML = cards.join("");
  grid.querySelectorAll("td[data-step]").forEach(td => {
    td.addEventListener("click", () => {
      APP.stepKey = td.dataset.step;
      APP.cellIdx = parseInt(td.dataset.idx, 10);
      renderRoundsTab();
    });
  });

  renderInspector(r1, isEnc);
}

function renderInspector(rData, isEnc) {
  const idx = APP.cellIdx, r = idx % 4, c = Math.floor(idx / 4), step = APP.stepKey;
  document.getElementById("insp-coord").textContent = `Seçili: s[${r},${c}] (${idx + 1}. Bayt) — Adım: ${step}`;
  const box = document.getElementById("insp-content");
  let sboxHl = null;

  if (step === "afterSub") {
    const inB = isEnc ? rData.input[idx] : rData.afterShift[idx];
    const outB = rData.afterSub[idx];
    const inv = GF.inv(inB);
    sboxHl = { byte: inB, inv: !isEnc };
    box.innerHTML = `
      <div class="formula-box">
        <strong>Tahtada Gösterim:</strong> Girdi baytı <strong>${hex2(inB)}</strong> &rarr; S-Box'ta <strong>${hex2(inB)[0]}. satır, ${hex2(inB)[1]}. sütun</strong> kesişimine bakılır &rarr; Sonuç: <strong>${hex2(outB)}</strong>
      </div>
      <table class="data-table">
        <thead><tr><th>S-Box Üretim Aşaması (Hoca Sorarsa)</th><th>Hex</th><th>8-Bit İkilik</th></tr></thead>
        <tbody>
          <tr><td>1. Girdi Baytı</td><td>${hex2(inB)}</td><td>${bin8(inB)}</td></tr>
          <tr><td>2. GF(2^8) Çarpımsal Tersi (mod 0x11B)</td><td>${hex2(inv)}</td><td>${bin8(inv)}</td></tr>
          <tr><td>3. Bit Karıştırma + Sabit 0x63 ile XOR</td><td><strong>${hex2(outB)}</strong></td><td><strong>${bin8(outB)}</strong></td></tr>
        </tbody>
      </table>`;
  } else if (step === "afterShift") {
    const srcCol = isEnc ? (c + r) % 4 : (c - r + 4) % 4;
    const val = rData.afterShift[idx];
    box.innerHTML = `
      <div class="formula-box">
        <strong>Satır Kaydırma Mantığı:</strong> ${r + 1}. satır (indeks ${r}) toplam <strong>${r} kutu ${isEnc ? "sola" : "sağa"}</strong> kaydırılır.<br>
        Bu sayede <strong>s[${r},${srcCol}]</strong> hücresindeki <strong>${hex2(val)}</strong> baytı, <strong>s[${r},${c}]</strong> konumuna geçerek farklı bir sütuna yerleşir.
      </div>`;
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
      if (k === 1) exp = `1 ile çarpım kendisidir: ${hex2(b)}`;
      else if (k === 2) exp = `1 bit sola kaydır: ${hex2(sh)} ${msb ? `(8 bitten taştı, 1B ile XOR: ${hex2(sh)} ⊕ 1B = ${hex2(p)})` : "(Taşma yok)"}`;
      else if (k === 3) exp = `(2 • ${hex2(b)}) ⊕ ${hex2(b)} = ${hex2(GF.mul(2, b))} ⊕ ${hex2(b)} = ${hex2(p)}`;
      else exp = `GF(2^8) polinomsal çarpım: ${hex2(k)} • ${hex2(b)} = ${hex2(p)}`;
      return `<tr><td>${hex2(k)} • ${hex2(b)}</td><td>${exp}</td><td><strong>${hex2(p)}</strong></td><td>${bin8(p)}</td></tr>`;
    }).join("");

    box.innerHTML = `
      <div class="formula-box">
        <strong>Sütun ${c} Karıştırma Denklemi:</strong>
        (${hex2(cf[0])}•${hex2(col[0])}) ⊕ (${hex2(cf[1])}•${hex2(col[1])}) ⊕ (${hex2(cf[2])}•${hex2(col[2])}) ⊕ (${hex2(cf[3])}•${hex2(col[3])}) = <strong>${hex2(outVal)}</strong>
      </div>
      <table class="data-table">
        <thead><tr><th>Çarpım</th><th>Tahtada Adım Adım Hesaplama</th><th>Hex</th><th>8-Bit İkilik (Alt Alta XOR)</th></tr></thead>
        <tbody>
          ${rows}
          <tr><th colspan="2">4 Terimin XOR Toplamı</th><th>${hex2(outVal)}</th><th>${bin8(outVal)}</th></tr>
        </tbody>
      </table>`;
  } else {
    const pre = APP.roundIdx === 0 ? rData.input : (isEnc ? (rData.afterMix || rData.afterShift) : rData.afterSub);
    const a = pre[idx], k = rData.rk[idx], res = rData.afterKey[idx];
    box.innerHTML = `
      <div class="formula-box">
        <strong>AddRoundKey (XOR Mühürleme):</strong> Aynı bitler 0, farklı bitler 1 verir. Aynı anahtarla tekrar XOR yapılırsa ilk sayı geri döner.
      </div>
      <table class="data-table">
        <thead><tr><th>Değer</th><th>Hex</th><th>8-Bit İkilik Karşılığı</th></tr></thead>
        <tbody>
          <tr><td>Tablodaki Bayt s[${r},${c}]</td><td>${hex2(a)}</td><td>${bin8(a)}</td></tr>
          <tr><td>Anahtar Baytı k[${r},${c}]</td><td>${hex2(k)}</td><td>${bin8(k)}</td></tr>
          <tr><th>XOR Sonucu (${hex2(a)} ⊕ ${hex2(k)})</th><th>${hex2(res)}</th><th>${bin8(res)}</th></tr>
        </tbody>
      </table>`;
  }

  renderSBox(sboxHl);
}

function renderSBox(hl) {
  const isInv = hl ? hl.inv : (APP.tab === "dec");
  const tbl = isInv ? TABLES.invSbox : TABLES.sbox;
  const hitR = hl ? (hl.byte >> 4) : -1, hitC = hl ? (hl.byte & 0x0f) : -1;

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
  const { W, logs, roundKeys } = APP.keyData;
  let rows = "";
  for (let r = 0; r <= 10; r++) {
    rows += `<tr><th>Tur ${r}</th>`;
    for (let c = 0; c < 4; c++) {
      const wi = r * 4 + c;
      rows += `<td><button type="button" class="w-btn ${APP.wordIdx === wi ? "active" : ""}" data-w="${wi}">W[${wi}]: ${W[wi].map(hex2).join("")}</button></td>`;
    }
    rows += `<td>${hexStr(roundKeys[r])}</td></tr>`;
  }
  const container = document.getElementById("key-schedule-table");
  container.innerHTML = `<table class="data-table"><thead><tr><th>Tur</th><th>1. Sütun</th><th>2. Sütun</th><th>3. Sütun</th><th>4. Sütun</th><th>16 Bayt Tur Anahtarı</th></tr></thead><tbody>${rows}</tbody></table>`;

  container.querySelectorAll(".w-btn").forEach(b => {
    b.addEventListener("click", () => {
      APP.wordIdx = parseInt(b.dataset.w, 10);
      renderKeyTab();
    });
  });

  const lg = logs[APP.wordIdx];
  const out = document.getElementById("key-insp-content");
  document.getElementById("key-insp-title").textContent = `W[${APP.wordIdx}] Sütunu Nasıl Üretildi?`;

  if (lg.type === "init") {
    out.innerHTML = `<div class="formula-box"><strong>W[${lg.i}] = [${hexStr(lg.word)}]</strong><br>İlk 4 sütun (W[0]..W[3]) doğrudan başlangıç gizli anahtarından alınır.</div>`;
  } else if (lg.type === "rot") {
    out.innerHTML = `
      <div class="formula-box"><strong>4'ün Katı Özel Anahtar Türetmesi:</strong> W[${lg.i}] = W[${lg.i - 4}] ⊕ SubWord(RotWord(W[${lg.i - 1}])) ⊕ Rcon[${lg.i / 4}]</div>
      <table class="data-table">
        <tbody>
          <tr><th>1. Bir Önceki Sütun W[${lg.i - 1}]</th><td>${hexStr(lg.prev)}</td></tr>
          <tr><th>2. RotWord (1 Bayt Sola Döndür)</th><td>${hexStr(lg.rot)}</td></tr>
          <tr><th>3. SubWord (S-Box'tan Geçir)</th><td>${hexStr(lg.sub)}</td></tr>
          <tr><th>4. Tur Sabiti Rcon[${lg.i / 4}] (${hex2(lg.rc)} 00 00 00) ile XOR</th><td>${hexStr(lg.rconXor)}</td></tr>
          <tr><th>5. 4 Adım Önceki Sütun W[${lg.i - 4}]</th><td>${hexStr(lg.prev4)}</td></tr>
          <tr><th>6. Sonuç W[${lg.i}] (Adım 4 ⊕ Adım 5)</th><td><strong>${hexStr(lg.word)}</strong></td></tr>
        </tbody>
      </table>`;
  } else {
    out.innerHTML = `
      <div class="formula-box"><strong>Standart Sütun Türetmesi:</strong> W[${lg.i}] = W[${lg.i - 4}] ⊕ W[${lg.i - 1}]</div>
      <table class="data-table">
        <tbody>
          <tr><th>W[${lg.i - 4}] Sütunu</th><td>${hexStr(lg.prev4)}</td></tr>
          <tr><th>W[${lg.i - 1}] Sütunu</th><td>${hexStr(lg.prev)}</td></tr>
          <tr><th>XOR Sonucu W[${lg.i}]</th><td><strong>${hexStr(lg.word)}</strong></td></tr>
        </tbody>
      </table>`;
  }
}

function renderCurrentTab() {
  document.getElementById("tab-prep").classList.toggle("active", APP.tab === "prep");
  document.getElementById("tab-rounds").classList.toggle("active", APP.tab === "enc" || APP.tab === "dec");
  document.getElementById("tab-key").classList.toggle("active", APP.tab === "key");

  if (APP.tab === "prep") renderPrepTab();
  else if (APP.tab === "enc" || APP.tab === "dec") renderRoundsTab();
  else if (APP.tab === "key") renderKeyTab();
}

document.addEventListener("DOMContentLoaded", () => {
  ["pt1-input", "pt2-input", "key-input"].forEach(id => {
    document.getElementById(id).addEventListener("input", updateAll);
  });
  document.getElementById("pad-select").addEventListener("change", updateAll);
  document.getElementById("show-diff-chk").addEventListener("change", e => {
    APP.showDiff = e.target.checked;
    renderRoundsTab();
  });

  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      APP.tab = btn.dataset.tab;
      APP.roundIdx = 1;
      APP.stepKey = "afterSub";
      renderRoundButtons();
      renderCurrentTab();
    });
  });

  updateAll();
});