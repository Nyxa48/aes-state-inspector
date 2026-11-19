"use strict";

const Core = typeof window !== "undefined" ? window.AESCore : require("./aes.js");
const Prefs = typeof window !== "undefined" ? window.UIPrefs : require("./ui-prefs.js");

const { CONSTANTS, Format, Layout, TABLES, AES, countBitDiff, getRoundSteps, normalizeStepKey, computeDependencies, computeCellTrace, computeAvalanche } = Core;
const { hex2, bin8, hexStr, isPrintableAscii } = Format;

const WORKBENCH_TABS = ["prep", "enc", "key", "dec"];

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const I18N = {
  tr: {
    pageTitle: "AES-128 İnteraktif Kriptoloji Laboratuvarı",
    skipLink: "İçeriğe atla",
    appTitle: "AES-128 Simetrik Blok Şifreleme Laboratuvarı",
    slidesLink: "Sunum Slaytları",
    presentBtn: "Sunum Modu",
    themeLight: "Açık Tema",
    themeDark: "Koyu Tema",
    markerBtn: "Tahta İşaretçisi (H)",
    markerTitle: "Tahta işaretçisi modunu aç/kapat (veya herhangi bir hücreye Shift+Tık yapın)",
    clearPinsLabel: "İşaretleri Temizle",
    legTarget: "Seçili hedef",
    legSrc: "Kaynak girdi",
    legKey: "Anahtar / Sonraki adım",
    legDiff: "Çığ etkisi farkı",
    legPin: "Tahta işareti (Shift+Tık)",
    roleSrc: "GİRDİ",
    roleKey: "ANAHTAR",
    roleNext: "SONRAKİ",
    rolePin: "İŞARET",
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
    khPresent: "Sunum",
    khMark: "İşaretçi",
    khNotes: "Notlar",
    khTheme: "Tema",
    notesOpenAll: "Tüm Notları Aç",
    notesCloseAll: "Notları Kapat",
    diffToggle: (name) => `<strong>${name}</strong> farklarını matriste işaretle`,
    noteTitle: "Bilgi Notu",
    prepNoteMeta: "Adım 0 özeti",
    roundNoteMeta: "Tur akışı özeti",
    inspNoteMeta: "Matematiksel kanıt",
    keyNoteMeta: "Key Schedule özeti",
    prepGuide: "<strong>Blok hazırlama özeti:</strong> Giriş metni ASCII baytlarına dönüştürülür, seçilen dolgu yöntemiyle 16 bayta (128 bit) tamamlanır ve 4×4 durum matrisine sütun-öncelikli (column-major) sırayla yerleştirilir.",
    prepNotes: `<ul>
      <li><strong>Sütun-öncelikli dizilim:</strong> İlk dört bayt (<code>A R A B</code>) birinci satıra değil, birinci sütuna yukarıdan aşağıya yazılır. 5. bayt olan ikinci <code>A</code> ise <code>s[0,1]</code> hücresine geçer.</li>
      <li><strong>2 bitlik fark vurgusu:</strong> <code>A</code> (<code>0x41 = 01000001</code>) ile <code>B</code> (<code>0x42 = 01000010</code>) arasında yalnızca 2 bit fark vardır; sağdaki çığ etkisi tablosu bu farkın 2. tur sonunda tüm 16 bayta yayıldığını gösterir.</li>
    </ul>`,
    keyGuide: "<strong>Anahtar genişletme mantığı:</strong> 16 baytlık başlangıç anahtarından 11 tur için toplam 44 adet 32-bit kelime (<code>W[0]..W[43]</code>) üretilir. İndeksi 4'ün katı olan kelimelerde sırasıyla <code>RotWord</code>, <code>SubWord</code> ve <code>Rcon</code> XOR işlemleri uygulanır.",
    keyNotes: `<ul>
      <li><strong>Neden 44 kelime?</strong> Her 4×4 tur anahtarı 4 sütundan (kelimeden) oluşur. Başlangıç (Tur 0) + 10 şifreleme turu = 11 tur × 4 sütun = 44 kelime.</li>
      <li><strong><code>W[4]</code> örneği:</strong> Tablodan <code>W[4]</code> butonu seçildiğinde sağda 6 adımlı hesap görünür: <code>W[3]</code> 1 bayt sola döner, S-Box'a girer, <code>Rcon[1] = 01 00 00 00</code> ile XOR'lanır ve <code>W[0]</code> ile birleştirilir.</li>
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
    prepStateSub: "Herhangi bir satıra veya hücreye tıklayarak ASCII dönüşümü ile matris konumu arasındaki bağlantıyı görün.",
    prepSelectedExplain: (idx, r, c, ch1, hex1, ch2, hex2, diffBits, isDiff) =>
      `<strong>Şu an seçili · ${idx + 1}. Bayt → s[${r},${c}]:</strong> Sütun-öncelikli kural gereği <code>satır = ${idx} % 4 = ${r}</code> ve <code>sütun = ⌊${idx} / 4⌋ = ${c}</code> konumuna yerleşir. Ana metin değeri <code>${ch1}</code> (<code>0x${hex1}</code>)${isDiff ? `; karşılaştırma metnindeki <code>${ch2}</code> (<code>0x${hex2}</code>) ile burada <strong>${diffBits} bitlik</strong> başlangıç farkı oluşur` : `, karşılaştırma metniyle aynıdır`}.`,
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
    rndDecN: (i, targetRound) => `Ters Adım ${i} (Tur ${targetRound})`,
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
    noteEncMix: "<ul><li><strong>Karışıklık ve yayılma:</strong> <code>SubBytes</code> karışıklık (confusion), <code>ShiftRows</code> ve <code>MixColumns</code> ise yayılma (diffusion) sağlar.</li><li><strong>Tur 1 ve Tur 2 farkı:</strong> Tur 1'de kırmızı fark yalnızca 2. sütunda (Sütun 1, 4 bayt) toplanır; Tur 2'deki <code>ShiftRows</code> bu baytları 4 farklı sütuna dağıtır ve <code>MixColumns</code> tüm 16 baytı değiştirir.</li></ul>",
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
    cEncKeyTitle: (hasMix) => (hasMix ? "4. AddRoundKey" : "3. AddRoundKey (Son Tur)"),
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
    explainInput: (r, c, round, nextLabel) =>
      round === 0
        ? `<strong>Bu anda ne oluyor?</strong> <code>s[${r},${c}]</code> hücresi ham giriş bloğundan gelen bayttır. Yeşil ile işaretlenen <strong>${nextLabel}</strong> adımında Tur anahtarı baytıyla XOR'lanır.`
        : `<strong>Bu anda ne oluyor?</strong> <code>s[${r},${c}]</code> bir önceki turun çıkışından gelen girdi baytıdır. Yeşil ile işaretlenen <strong>${nextLabel}</strong> adımına doğrudan kaynaklık eder.`,
    explainRk: (r, c, wi) =>
      `<strong>Bu anda ne oluyor?</strong> Seçili <code>k[${r},${c}]</code> anahtar baytı, <code>W[${wi}]</code> anahtar sütununun ${r + 1}. baytıdır. Amber renkteki giriş baytı ile XOR'lanarak yeşil çıkış hücresini üretir.`,
    explainSub: (inB, outB, isEnc) =>
      `<strong>Bu anda ne oluyor (${isEnc ? "Karışıklık / Confusion" : "Ters İkame"}):</strong> Amber ile işaretli girdi baytı <code>${inB}</code>, diğer hücrelerden tamamen bağımsız biçimde kendi içinde <code>GF(2⁸)</code> tersi + afin dönüşümden geçerek <code>${outB}</code> değerine dönüşür.`,
    explainShift: (r, c, srcCol, dir) =>
      `<strong>Bu anda ne oluyor (Sütunlar Arası Geçiş):</strong> Önceki matrisin ${r + 1}. satırındaki 4 bayt <strong>${r} birim ${dir}</strong> kaydırılır. Amber ile işaretli <code>s[${r},${srcCol}]</code> hücresi bu sayede farklı bir sütun olan <code>s[${r},${c}]</code> konumuna gelir.`,
    explainMix: (c, isEnc) =>
      `<strong>Bu anda ne oluyor (${isEnc ? "Yayılma / Diffusion" : "Ters Sütun Çarpımı"}):</strong> Hedef hücre <code>s[*,${c}]</code>, yalnızca tek bir bayttan değil; önceki matriste <strong>Amber ile vurgulanan Sütun ${c} (${c + 1}. sütun) içindeki 4 baytın tamamının</strong> MDS matrisiyle <code>GF(2⁸)</code> çarpımından üretilir.`,
    explainKey: (r, c, wi, round) =>
      `<strong>Bu anda ne oluyor (Anahtar Mühürleme):</strong> Amber ile vurgulanan durum baytı <code>s[${r},${c}]</code> ile Tur ${round} anahtarının <code>W[${wi}]</code> sütunundaki <code>k[${r},${c}]</code> baytı bit düzeyinde XOR'lanır.`,
    inspSubBox: (inB, boxName, hi, lo, outB) => `<strong>Tablo kesişimi:</strong> Girdi baytı <strong>${inB}</strong> → ${boxName} üzerinde <strong>${hi}</strong> satırı, <strong>${lo}</strong> sütunu → Sonuç: <strong>${outB}</strong>`,
    inspSubHead: "GF(2⁸) üretim aşamaları",
    inspBinCol: "8-bit ikilik",
    inspSubR1: "1. Girdi baytı (Amber)",
    inspSubR2: "2. Çarpımsal ters (mod 0x11B)",
    inspSubR3: "3. Afin dönüşüm + 0x63 XOR",
    proofSummary: "Adım adım afin bit açılımı ve GF(2⁸) ters doğrulaması",
    proofInvZero: "0x00 baytının GF(2⁸) tersi tanım gereği 0x00 kabul edilir.",
    proofInvMul: (a, inv, prod) => `Ters doğrulama: GF.mul(${a}, ${inv}) = ${prod} (mod 0x11B)`,
    proofAffHead: "Afin bit döndürme toplama açılımı (b' = b ⊕ (b≪1) ⊕ (b≪2) ⊕ (b≪3) ⊕ (b≪4) ⊕ 0x63):",
    proofInvAffHead: "Ters S-Box sırası: önce (y ≪ 1) ⊕ (y ≪ 3) ⊕ (y ≪ 6) ⊕ 0x05, ardından mod 0x11B tersi:",
    inspSubNote: "<ul><li><strong>Cebirsel üretim:</strong> S-Box sabit ezberlenmiş bir tablo değildir; <code>0x11B</code> (x⁸ + x⁴ + x³ + x + 1) polinomu altında çarpımsal ters alınıp afin matris ve <code>0x63</code> sabiti ile sabit noktası (<code>S(x)=x</code>) olmayacak şekilde üretilir.</li></ul>",
    inspShiftBox: (row1, r, dir, srcCol, val, c) => `<strong>Satır kaydırma:</strong> ${row1}. satır (indeks ${r}) toplam <strong>${r}</strong> birim ${dir} kaydırılır. <strong>s[${r},${srcCol}]</strong> → <strong>s[${r},${c}]</strong> (${val}).`,
    shiftBefore: "Önceki satır:",
    shiftAfter: "Kaydırılmış satır:",
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
    rkStripLabel: (wi, r) => `Tur Anahtarı sütunu W[${wi}] (${r + 1}. bayt seçili):`,
    jumpWordBtn: (wi) => `W[${wi}] Türetimine Git →`,
    colVal: "Değer",
    inspKeyR1: (r, c) => `Durum baytı s[${r},${c}] (Amber)`,
    inspKeyR2: (r, c) => `Anahtar baytı k[${r},${c}] (Yeşil)`,
    inspKeyRes: (a, k) => `XOR sonucu (${a} ⊕ ${k})`,
    inspKeyNote: "<ul><li><strong>Neden toplama değil XOR?</strong> XOR bit bazında kendi kendinin tersidir (<code>(A ⊕ K) ⊕ K = A</code>) ve taşıma (carry) üretmediği için sabit zamanda donanım dostu çalışır.</li></ul>",
    keyTabCols: ["Tur", "1. Sütun", "2. Sütun", "3. Sütun", "4. Sütun", "16 bayt tur anahtarı"],
    keyRoundLbl: (r) => `Tur ${r}`,
    keyInspTitle: (w) => `W[${w}] Sütunu Türetimi`,
    keyExplainInit: (i) => `<strong>Bu anda ne oluyor?</strong> <code>W[${i}]</code> başlangıç anahtarının doğrudan kopyasıdır (Tur 0'da kullanılır).`,
    keyExplainRot: (i, prevIdx, prev4Idx) => `<strong>Bu anda ne oluyor (4'ün Katı Özel Adımı)?</strong> İndeks 4'ün katı olduğu için bir önceki sütun (<code>W[${prevIdx}]</code>, Amber) döndürülür, S-Box'tan geçirilir, tur sabitiyle XOR'lanır ve 4 önceki sütunla (<code>W[${prev4Idx}]</code>, Yeşil) birleştirilir.`,
    keyExplainXor: (prevIdx, prev4Idx) => `<strong>Bu anda ne oluyor?</strong> Standart sütun türetmesinde bir önceki sütun (<code>W[${prevIdx}]</code>, Amber) ile 4 adım önceki sütun (<code>W[${prev4Idx}]</code>, Yeşil) doğrudan XOR'lanır.`,
    keyInitBox: (i, w) => `<strong>W[${i}] = [${w}]</strong><br>İlk 4 kelime (W[0]..W[3]) doğrudan 128-bit başlangıç gizli anahtarından kopyalanır.`,
    keyRotBox: (i, prevIdx, prev4Idx, rconIdx) => `<strong>4'ün katı kelime türetimi:</strong> W[${i}] = W[${prev4Idx}] ⊕ SubWord(RotWord(W[${prevIdx}])) ⊕ Rcon[${rconIdx}]`,
    keyRotR1: (prevIdx) => `1. Önceki kelime W[${prevIdx}] (Amber)`,
    keyRotR2: "2. RotWord (1 bayt sola döndür)",
    keyRotR3: "3. SubWord (S-Box dönüşümü)",
    keyRotR4: (r, rc) => `4. Rcon[${r}] (${rc} 00 00 00) ile XOR`,
    keyRotR5: (prev4Idx) => `5. W[${prev4Idx}] kelimesi (Yeşil)`,
    keyRotR6: (i) => `6. Sonuç W[${i}] (Adım 4 ⊕ Adım 5)`,
    keyXorBox: (i, prevIdx, prev4Idx) => `<strong>Standart kelime türetimi:</strong> W[${i}] = W[${prev4Idx}] ⊕ W[${prevIdx}]`,
    keyXorR1: (prev4Idx) => `W[${prev4Idx}] kelimesi (Yeşil)`,
    keyXorR2: (prevIdx) => `W[${prevIdx}] kelimesi (Amber)`,
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
    markerBtn: "Board Highlighter (H)",
    markerTitle: "Toggle Board Highlighter mode (or Shift+Click any cell)",
    clearPinsLabel: "Clear Marks",
    legTarget: "Selected target",
    legSrc: "Source input",
    legKey: "Key / Next step",
    legDiff: "Avalanche diff",
    legPin: "Pinned mark (Shift+Click)",
    roleSrc: "INPUT",
    roleKey: "KEY",
    roleNext: "NEXT",
    rolePin: "PIN",
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
    khPresent: "Present",
    khMark: "Highlighter",
    khNotes: "Notes",
    khTheme: "Theme",
    notesOpenAll: "Open All Notes",
    notesCloseAll: "Close Notes",
    diffToggle: (name) => `Highlight <strong>${name}</strong> differences in matrices`,
    noteTitle: "Study Note",
    prepNoteMeta: "Step 0 summary",
    roundNoteMeta: "Round flow summary",
    inspNoteMeta: "Mathematical proof",
    keyNoteMeta: "Key Schedule summary",
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
    prepStateSub: "Click any byte row or cell to link its ASCII conversion directly to its column-major coordinate.",
    prepSelectedExplain: (idx, r, c, ch1, hex1, ch2, hex2, diffBits, isDiff) =>
      `<strong>Currently selected · Byte ${idx + 1} → s[${r},${c}]:</strong> By column-major indexing, <code>row = ${idx} % 4 = ${r}</code> and <code>col = ⌊${idx} / 4⌋ = ${c}</code>. Primary byte is <code>${ch1}</code> (<code>0x${hex1}</code>)${isDiff ? `; compared with <code>${ch2}</code> (<code>0x${hex2}</code>) this creates a <strong>${diffBits}-bit</strong> initial delta` : `, matching the comparison block`}.`,
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
    rndDecN: (i, targetRound) => `Inv Step ${i} (Round ${targetRound})`,
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
    cEncKeyTitle: (hasMix) => (hasMix ? "4. AddRoundKey" : "3. AddRoundKey (Final)"),
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
    explainInput: (r, c, round, nextLabel) =>
      round === 0
        ? `<strong>What is happening here:</strong> Cell <code>s[${r},${c}]</code> holds the initial input byte. Next, it is XORed with the round key byte at the Emerald-highlighted <strong>${nextLabel}</strong> step.`
        : `<strong>What is happening here:</strong> Cell <code>s[${r},${c}]</code> enters from the previous round and feeds directly into the Emerald-highlighted <strong>${nextLabel}</strong> cell.`,
    explainRk: (r, c, wi) =>
      `<strong>What is happening here:</strong> Selected key byte <code>k[${r},${c}]</code> is byte ${r + 1} of word <code>W[${wi}]</code>. It XORs with the Amber input cell to produce the Emerald output cell.`,
    explainSub: (inB, outB, isEnc) =>
      `<strong>What is happening here (${isEnc ? "Confusion" : "Inverse Substitution"}):</strong> The Amber input byte <code>${inB}</code> is transformed independently of all neighbors via <code>GF(2⁸)</code> inversion + affine mapping to yield <code>${outB}</code>.`,
    explainShift: (r, c, srcCol, dir) =>
      `<strong>What is happening here (Cross-Column Mixing):</strong> All 4 bytes in row ${r + 1} rotate <strong>${r} steps ${dir}</strong>. Thus the Amber cell <code>s[${r},${srcCol}]</code> moves into column ${c} at <code>s[${r},${c}]</code>.`,
    explainMix: (c, isEnc) =>
      `<strong>What is happening here (${isEnc ? "Diffusion" : "Inverse Mixing"}):</strong> Target <code>s[*,${c}]</code> depends on <strong>all 4 bytes of Column ${c}</strong> (highlighted in Amber) multiplied by the MDS matrix in <code>GF(2⁸)</code>.`,
    explainKey: (r, c, wi, round) =>
      `<strong>What is happening here (Key Mixing):</strong> The Amber state byte <code>s[${r},${c}]</code> is XORed bitwise with byte <code>k[${r},${c}]</code> from word <code>W[${wi}]</code> of Round ${round}'s key.`,
    inspSubBox: (inB, boxName, hi, lo, outB) => `<strong>Table lookup:</strong> Input byte <strong>${inB}</strong> → ${boxName} row <strong>${hi}</strong>, column <strong>${lo}</strong> → Result: <strong>${outB}</strong>`,
    inspSubHead: "GF(2⁸) derivation stages",
    inspBinCol: "8-bit binary",
    inspSubR1: "1. Input byte (Amber)",
    inspSubR2: "2. Multiplicative inverse (mod 0x11B)",
    inspSubR3: "3. Affine transform + 0x63 XOR",
    proofSummary: "Step-by-step affine bit expansion & GF(2⁸) inverse proof",
    proofInvZero: "By definition, the GF(2⁸) inverse of 0x00 is 0x00.",
    proofInvMul: (a, inv, prod) => `Inverse check: GF.mul(${a}, ${inv}) = ${prod} (mod 0x11B)`,
    proofAffHead: "Affine bit-rotation XOR expansion (b' = b ⊕ (b≪1) ⊕ (b≪2) ⊕ (b≪3) ⊕ (b≪4) ⊕ 0x63):",
    proofInvAffHead: "Inverse S-Box order: first (y≪1) ⊕ (y≪3) ⊕ (y≪6) ⊕ 0x05, then mod 0x11B inverse:",
    inspSubNote: "<ul><li><strong>Algebraic construction:</strong> The S-Box is not arbitrary; each byte takes its multiplicative inverse modulo <code>0x11B</code> (x⁸ + x⁴ + x³ + x + 1) followed by an affine map + <code>0x63</code> XOR to eliminate fixed points (<code>S(x)=x</code>).</li></ul>",
    inspShiftBox: (row1, r, dir, srcCol, val, c) => `<strong>Row rotation:</strong> Row ${row1} (index ${r}) shifts <strong>${r}</strong> positions ${dir}. <strong>s[${r},${srcCol}]</strong> → <strong>s[${r},${c}]</strong> (${val}).`,
    shiftBefore: "Before shift:",
    shiftAfter: "After shift:",
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
    rkStripLabel: (wi, r) => `Round key word W[${wi}] (byte ${r + 1} active):`,
    jumpWordBtn: (wi) => `Inspect W[${wi}] Derivation →`,
    colVal: "Value",
    inspKeyR1: (r, c) => `State byte s[${r},${c}] (Amber)`,
    inspKeyR2: (r, c) => `Key byte k[${r},${c}] (Emerald)`,
    inspKeyRes: (a, k) => `XOR result (${a} ⊕ ${k})`,
    inspKeyNote: "<ul><li><strong>Why XOR instead of addition?</strong> XOR is its own inverse (<code>(A ⊕ K) ⊕ K = A</code>) and generates no carries, running in constant time without side-channel carry timing.</li></ul>",
    keyTabCols: ["Round", "Col 1", "Col 2", "Col 3", "Col 4", "16-byte round key"],
    keyRoundLbl: (r) => `Round ${r}`,
    keyInspTitle: (w) => `Derivation of Word W[${w}]`,
    keyExplainInit: (i) => `<strong>What is happening here:</strong> <code>W[${i}]</code> is copied directly from the initial 128-bit secret key (used in Round 0).`,
    keyExplainRot: (i, prevIdx, prev4Idx) => `<strong>What is happening here (Multiple-of-4 Step):</strong> Because index ${i} is a multiple of 4, the previous word (<code>W[${prevIdx}]</code>, Amber) rotates left, passes through the S-Box, XORs with <code>Rcon</code>, and combines with <code>W[${prev4Idx}]</code> (Emerald).`,
    keyExplainXor: (prevIdx, prev4Idx) => `<strong>What is happening here:</strong> Standard word expansion XORs the previous word (<code>W[${prevIdx}]</code>, Amber) with the word 4 steps back (<code>W[${prev4Idx}]</code>, Emerald).`,
    keyInitBox: (i, w) => `<strong>W[${i}] = [${w}]</strong><br>The first 4 words (W[0]..W[3]) are copied directly from the initial 128-bit cipher key.`,
    keyRotBox: (i, prevIdx, prev4Idx, rconIdx) => `<strong>Multiple-of-4 derivation:</strong> W[${i}] = W[${prev4Idx}] ⊕ SubWord(RotWord(W[${prevIdx}])) ⊕ Rcon[${rconIdx}]`,
    keyRotR1: (prevIdx) => `1. Previous word W[${prevIdx}] (Amber)`,
    keyRotR2: "2. RotWord (rotate left 1 byte)",
    keyRotR3: "3. SubWord (S-Box substitution)",
    keyRotR4: (r, rc) => `4. XOR with Rcon[${r}] (${rc} 00 00 00)`,
    keyRotR5: (prev4Idx) => `5. Word W[${prev4Idx}] (Emerald)`,
    keyRotR6: (i) => `6. Result W[${i}] (Step 4 ⊕ Step 5)`,
    keyXorBox: (i, prevIdx, prev4Idx) => `<strong>Standard derivation:</strong> W[${i}] = W[${prev4Idx}] ⊕ W[${prevIdx}]`,
    keyXorR1: (prev4Idx) => `Word W[${prev4Idx}] (Emerald)`,
    keyXorR2: (prevIdx) => `Word W[${prevIdx}] (Amber)`,
    keyXorR3: (i) => `XOR result W[${i}]`
  }
};

const APP = {
  lang: "tr",
  tab: "prep",
  roundIdx: 1,
  stepKey: "afterSub",
  cellIdx: 0,
  prepCellIdx: 4,
  wordIdx: 4,
  showDiff: true,
  presentMode: false,
  markerMode: false,
  pins: new Set(),
  notesOpen: new Set(),
  pt1Str: CONSTANTS.DEFAULTS.pt1,
  pt2Str: CONSTANTS.DEFAULTS.pt2,
  pt1Info: null,
  pt2Info: null,
  keyInfo: null,
  pt1: [],
  pt2: [],
  keyData: null,
  enc1: [],
  enc2: [],
  dec1: [],
  inDiff: null,
  outDiff: null,
  roundDiffs: []
};

const STATIC_TEXT_BINDINGS = [
  ["skip-link", "skipLink"],
  ["app-title", "appTitle"],
  ["slides-link", "slidesLink"],
  ["present-btn-label", "presentBtn"],
  ["marker-btn-label", "markerBtn"],
  ["clear-pins-label", "clearPinsLabel"],
  ["leg-target", "legTarget"],
  ["leg-src", "legSrc"],
  ["leg-key", "legKey"],
  ["leg-diff", "legDiff"],
  ["leg-pin", "legPin"],
  ["lbl-pt1", "lblPt1"],
  ["lbl-pt2", "lblPt2"],
  ["lbl-pad", "lblPad"],
  ["opt-pad-zero", "optZero"],
  ["opt-pad-pkcs7", "optPkcs7"],
  ["lbl-key", "lblKey"],
  ["tab-btn-prep", "tabPrep"],
  ["tab-btn-enc", "tabEnc"],
  ["tab-btn-key", "tabKey"],
  ["tab-btn-dec", "tabDec"],
  ["kh-tabs", "khTabs"],
  ["kh-step", "khStep"],
  ["kh-present", "khPresent"],
  ["kh-mark", "khMark"],
  ["kh-notes", "khNotes"],
  ["kh-theme", "khTheme"],
  ["prep-note-meta", "prepNoteMeta"],
  ["round-note-meta", "roundNoteMeta"],
  ["insp-note-meta", "inspNoteMeta"],
  ["key-note-meta", "keyNoteMeta"],
  ["insp-title", "inspTitle"],
  ["sbox-hint", "sboxHint"],
  ["key-table-title", "keyTableTitle"],
  ["key-table-hint", "keyTableHint"]
];

const STATIC_HTML_BINDINGS = [
  ["prep-guide", "prepGuide"],
  ["prep-note-body", "prepNotes"],
  ["key-guide", "keyGuide"],
  ["key-note-body", "keyNotes"]
];

function byId(id) {
  return document.getElementById(id);
}

function getDict() {
  return I18N[APP.lang];
}

function getStepLabel(step, isEnc) {
  const t = getDict();
  const labels = {
    input: t.stepInput,
    rk: t.stepRk,
    afterSub: isEnc ? t.stepSub : t.stepInvSub,
    afterShift: isEnc ? t.stepShift : t.stepInvShift,
    afterMix: isEnc ? t.stepMix : t.stepInvMix,
    afterKey: t.stepKey
  };
  return labels[step] || step;
}

function buildRoundCardSpec(stepKey, rData, roundIdx, isEnc) {
  const t = getDict();
  const hasMix = Boolean(rData.afterMix);
  if (roundIdx === 0) {
    return {
      input: { title: t.c0InTitle, desc: t.c0InDesc },
      rk: { title: t.c0RkTitle, desc: isEnc ? t.c0RkEnc : t.c0RkDec },
      afterKey: { title: t.c0KeyTitle, desc: t.c0KeyDesc }
    }[stepKey];
  }
  if (isEnc) {
    return {
      input: { title: t.cEncInTitle, desc: t.cEncInDesc(roundIdx - 1) },
      afterSub: { title: t.cEncSubTitle, desc: t.cEncSubDesc },
      afterShift: { title: t.cEncShiftTitle, desc: t.cEncShiftDesc },
      afterMix: { title: t.cEncMixTitle, desc: t.cEncMixDesc },
      afterKey: { title: t.cEncKeyTitle(hasMix), desc: t.cEncKeyDesc(roundIdx) }
    }[stepKey];
  }
  return {
    input: { title: t.cDecInTitle, desc: t.cDecInDesc },
    afterShift: { title: t.cDecShiftTitle, desc: t.cDecShiftDesc },
    afterSub: { title: t.cDecSubTitle, desc: t.cDecSubDesc },
    afterKey: { title: t.cDecKeyTitle, desc: t.cDecKeyDesc(rData.round) },
    afterMix: { title: t.cDecMixTitle, desc: t.cDecMixDesc }
  }[stepKey];
}

function togglePin(pinKey) {
  if (APP.pins.has(pinKey)) APP.pins.delete(pinKey);
  else APP.pins.add(pinKey);
  syncPinCounter();
  renderCurrentTab();
}

function syncPinCounter() {
  const btn = byId("clear-pins-btn");
  const cnt = byId("pin-count");
  if (cnt) cnt.textContent = String(APP.pins.size);
  if (btn) btn.hidden = APP.pins.size === 0;
}

function renderStateCell({ meta, valHex, diffHex, roleBadge, cls, attrs }) {
  return `<td tabindex="0" role="button" class="${cls}" ${attrs}>
    <div class="cell-box">
      <span class="cell-meta">${meta}</span>
      <span class="cell-val">${valHex}</span>
      <span class="cell-sub">${diffHex ? `<span class="diff-sub">≠ ${diffHex}</span>` : ""}${roleBadge}</span>
    </div>
  </td>`;
}

function updateFieldHints() {
  const t = getDict();
  const applyBlockHint = (info, elId) => {
    const el = byId(elId);
    if (!el || !info) return;
    if (info.mode === "hex") {
      el.textContent = t.hintHexBlock;
      el.classList.remove("warn");
    } else if (info.isTruncated) {
      el.textContent = t.hintTruncBlock(info.charLen);
      el.classList.add("warn");
    } else {
      el.textContent = t.hintAsciiBlock(info.charLen);
      el.classList.remove("warn");
    }
  };

  applyBlockHint(APP.pt1Info, "pt1-hint");
  applyBlockHint(APP.pt2Info, "pt2-hint");

  const pad = byId("pad-select").value;
  const padHint = byId("pad-hint");
  if (padHint) padHint.textContent = pad === "pkcs7" ? t.hintPadPkcs7 : t.hintPadZero;

  const keyHint = byId("key-hint");
  const ki = APP.keyInfo;
  if (keyHint && ki) {
    if (ki.hasInvalidChars) {
      keyHint.textContent = t.hintKeyDirty(Math.min(ki.hexCount, 32));
      keyHint.classList.add("warn");
    } else if (ki.isShort) {
      keyHint.textContent = t.hintKeyShort(ki.hexCount);
      keyHint.classList.add("warn");
    } else {
      keyHint.textContent = t.hintKeyOk;
      keyHint.classList.remove("warn");
    }
  }
}

function syncDerivedUi() {
  updateFieldHints();
  const toggleText = byId("diff-toggle-text");
  if (toggleText) toggleText.innerHTML = getDict().diffToggle(escapeHtml(APP.pt2Str || '""'));
  renderBanner();
  renderRoundButtons();
  renderCurrentTab();
}

function updateAll(render = true) {
  APP.pt1Str = byId("pt1-input").value;
  APP.pt2Str = byId("pt2-input").value;
  const pad = byId("pad-select").value;
  const res = computeAvalanche(APP.pt1Str, APP.pt2Str, byId("key-input").value, pad);

  APP.pt1Info = res.pt1Info;
  APP.pt2Info = res.pt2Info;
  APP.keyInfo = res.keyInfo;
  APP.pt1 = res.pt1;
  APP.pt2 = res.pt2;
  APP.keyData = res.keyData;
  APP.enc1 = res.enc1;
  APP.enc2 = res.enc2;
  APP.dec1 = res.dec1;
  APP.inDiff = res.inDiff;
  APP.outDiff = res.outDiff;
  APP.roundDiffs = res.roundDiffs;

  if (render) syncDerivedUi();
}

function renderBanner() {
  const t = getDict();
  const ct1 = APP.enc1[CONSTANTS.ROUNDS].afterKey;
  const ct2 = APP.enc2[CONSTANTS.ROUNDS].afterKey;
  const { inDiff, outDiff } = APP;
  const pt1Disp = escapeHtml(APP.pt1Str || '""');
  const pt2Disp = escapeHtml(APP.pt2Str || '""');

  const fmtDiffHex = (arr, ref) => arr.map((b, i) =>
    (b !== ref[i] ? `<span class="hl-diff" title="${t.bannerInTitle}: ${hex2(ref[i])}">${hex2(b)}</span>` : hex2(b))
  ).join(" ");

  byId("diff-banner").innerHTML = `
    <div class="banner-box">
      <span class="banner-label">${t.bannerMain(pt1Disp)}</span>
      <div class="banner-line"><span class="banner-key">${t.bannerIn}</span><span>${hexStr(APP.pt1)}</span></div>
      <div class="banner-line"><span class="banner-key">${t.bannerOut}</span><span><strong>${hexStr(ct1)}</strong></span></div>
    </div>
    <div class="banner-box">
      <span class="banner-label">${t.bannerCmp(pt2Disp)}</span>
      <div class="banner-line"><span class="banner-key">${t.bannerIn}</span><span>${fmtDiffHex(APP.pt2, APP.pt1)}</span></div>
      <div class="banner-line"><span class="banner-key">${t.bannerOut}</span><span><strong>${fmtDiffHex(ct2, ct1)}</strong></span></div>
    </div>
    <div class="aval-stat">
      <div class="aval-row"><span class="aval-row-label">${t.avalIn}</span><span class="aval-row-val">${t.fmtBytes(inDiff.bytes)} (${t.fmtBits(inDiff.bits)})</span></div>
      <div class="aval-row aval-out"><span class="aval-row-label">${t.avalOut}</span><span class="aval-row-val">${t.fmtBytes(outDiff.bytes)} · ${t.fmtBits(outDiff.bits)} (${t.fmtPct(outDiff.pct)})</span></div>
    </div>`;
}

function renderPrepTab() {
  const t = getDict();
  const pt1Label = escapeHtml(APP.pt1Str || '""');
  const pt2Label = escapeHtml(APP.pt2Str || '""');
  const selIdx = APP.prepCellIdx;

  let rows = "";
  for (let i = 0; i < 16; i++) {
    const b1 = APP.pt1[i];
    const b2 = APP.pt2[i];
    const { r, c } = Layout.coord(i);
    const ch1 = isPrintableAscii(b1) ? String.fromCharCode(b1) : t.padLbl;
    const ch2 = isPrintableAscii(b2) ? String.fromCharCode(b2) : t.padLbl;
    const isDiff = b1 !== b2;
    const isSel = i === selIdx;
    const cls = ["prep-row", isDiff ? "diff-row" : "", isSel ? "prep-selected" : "", APP.pins.has(`prep:${i}`) ? "pinned" : ""].filter(Boolean).join(" ");
    rows += `<tr tabindex="0" role="button" aria-pressed="${isSel}" class="${cls}" data-prep-idx="${i}">
      <td>${t.byteWord} ${i + 1} (s[${r},${c}])</td>
      <td>${escapeHtml(ch1)} → ${b1} → <strong>${hex2(b1)}</strong> (${bin8(b1)})</td>
      <td>${escapeHtml(ch2)} → ${b2} → <strong>${hex2(b2)}</strong> (${bin8(b2)})</td>
      <td>${isDiff ? t.bitDiffLbl(countBitDiff([b1], [b2]).bits) : t.sameLbl}</td>
    </tr>`;
  }

  let stateCells = "";
  for (let r = 0; r < 4; r++) {
    stateCells += "<tr>";
    for (let c = 0; c < 4; c++) {
      const idx = Layout.idx(r, c);
      const b1 = APP.pt1[idx];
      const b2 = APP.pt2[idx];
      const isSel = idx === selIdx;
      const isPin = APP.pins.has(`prep:${idx}`);
      const valHex = hex2(b1);
      const cls = [isSel ? "selected" : "", b1 !== b2 ? "diff-cell" : "", isPin ? "pinned" : ""].filter(Boolean).join(" ");
      stateCells += renderStateCell({
        meta: `${idx + 1}. ${t.byteWord} · s[${r},${c}]`,
        valHex,
        diffHex: b1 !== b2 ? hex2(b2) : "",
        roleBadge: isPin ? `<span class="role-tag role-tag-pin">${t.rolePin}</span>` : "",
        cls,
        attrs: `aria-pressed="${isSel}" aria-label="${t.byteWord} ${idx + 1} s[${r},${c}]: ${valHex}" data-prep-idx="${idx}"`
      });
    }
    stateCells += "</tr>";
  }

  const sb1 = APP.pt1[selIdx];
  const sb2 = APP.pt2[selIdx];
  const { r: selR, c: selC } = Layout.coord(selIdx);
  const sch1 = isPrintableAscii(sb1) ? `'${String.fromCharCode(sb1)}'` : t.padLbl;
  const sch2 = isPrintableAscii(sb2) ? `'${String.fromCharCode(sb2)}'` : t.padLbl;
  const selExplain = t.prepSelectedExplain(
    selIdx, selR, selC, escapeHtml(sch1), hex2(sb1), escapeHtml(sch2), hex2(sb2),
    countBitDiff([sb1], [sb2]).bits, sb1 !== sb2
  );

  const avalRows = APP.roundDiffs.map((d) => `<tr>
    <td>${d.round === 0 ? t.stageStart : t.stageEnd(d.round)}</td>
    <td>${d.bytes} / 16 ${t.unitByte}</td>
    <td><strong>${t.fmtBits(d.bits)} (${t.fmtPct(d.pct)})</strong></td>
  </tr>`).join("");

  byId("prep-content").innerHTML = `
    <div class="card">
      <div class="card-head"><h2 class="card-title-text">${t.prepAsciiHead(pt1Label, pt2Label)}</h2></div>
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
          <h2 class="card-title-text">${t.prepStateTitle}</h2>
          <span class="muted-note">${t.prepStateBadge}</span>
        </div>
        <p class="muted-note card-subtitle">${t.prepStateSub}</p>
        <div class="explain-box">${selExplain}</div>
        <div class="table-scroll"><table class="state-table state-table-prep"><tbody>${stateCells}</tbody></table></div>
      </div>
      <div class="card">
        <div class="card-head">
          <h2 class="card-title-text">${t.prepAvalTitle}</h2>
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
  const t = getDict();
  const ctrl = byId("round-controls");
  const isRoundTab = APP.tab === "enc" || APP.tab === "dec";
  ctrl.classList.toggle("visible", isRoundTab);
  const diffWrap = byId("diff-toggle-wrap");
  if (diffWrap) diffWrap.hidden = APP.tab !== "enc";
  if (!isRoundTab) return;

  let html = "";
  for (let i = 0; i <= CONSTANTS.ROUNDS; i++) {
    const lbl = APP.tab === "enc"
      ? (i === 0 ? t.rndEnc0 : t.rndEncN(i))
      : (i === 0 ? t.rndDec0 : t.rndDecN(i, CONSTANTS.ROUNDS - i));
    html += `<button type="button" class="${APP.roundIdx === i ? "active" : ""}" data-r="${i}">${lbl}</button>`;
  }
  byId("round-buttons").innerHTML = html;
}

function buildStateCard(title, desc, bytes, refBytes, stepKey, dep) {
  const t = getDict();
  const isCardActive = APP.stepKey === stepKey;
  const isCardSource = dep.sourceStep === stepKey;
  const cardCls = `matrix-card${isCardActive ? " card-active" : ""}${isCardSource ? " card-source" : ""}`;
  const pinPrefix = `${APP.tab}:${APP.roundIdx}:${stepKey}:`;

  let rows = "";
  for (let r = 0; r < 4; r++) {
    rows += "<tr>";
    for (let c = 0; c < 4; c++) {
      const idx = Layout.idx(r, c);
      const isSel = isCardActive && APP.cellIdx === idx;
      const isSrc = dep.sourceStep === stepKey && dep.sourceIndices.has(idx);
      const isKey = dep.keyStep === stepKey && dep.keyIndices.has(idx);
      const isRowBand = dep.rowBandStep === stepKey && dep.rowBandRow === r && !isSrc;
      const isPin = APP.pins.has(pinPrefix + idx);
      const hasDiff = APP.showDiff && APP.tab === "enc" && refBytes && bytes[idx] !== refBytes[idx];
      const valHex = hex2(bytes[idx]);
      const diffTxt = hasDiff ? `, ≠ ${hex2(refBytes[idx])}` : "";

      let roleBadge = "";
      if (isPin) roleBadge = `<span class="role-tag role-tag-pin">${t.rolePin}</span>`;
      else if (isSrc) roleBadge = `<span class="role-tag role-tag-src">${t.roleSrc}</span>`;
      else if (isKey) {
        const keyLabel = (APP.roundIdx === 0 && stepKey === "rk") ? t.roleKey : t.roleNext;
        roleBadge = `<span class="role-tag role-tag-key">${keyLabel}</span>`;
      }

      const cls = [
        isSel ? "selected" : "",
        hasDiff ? "diff-cell" : "",
        isSrc ? "src-cell" : "",
        isKey ? "key-cell" : "",
        isRowBand ? "row-band" : "",
        isPin ? "pinned" : ""
      ].filter(Boolean).join(" ");

      rows += renderStateCell({
        meta: `s[${r},${c}]`,
        valHex,
        diffHex: hasDiff ? hex2(refBytes[idx]) : "",
        roleBadge,
        cls,
        attrs: `aria-pressed="${isSel}" aria-label="${title} s[${r},${c}]: ${valHex}${diffTxt}" data-step="${stepKey}" data-idx="${idx}"`
      });
    }
    rows += "</tr>";
  }
  return `<div class="${cardCls}">
    <h3 class="matrix-title">${title}</h3>
    <div class="step-desc">${desc}</div>
    <table class="state-table"><tbody>${rows}</tbody></table>
  </div>`;
}

function renderAffineProof(affine, t) {
  let lines = "";
  if (affine.isEnc) {
    const invCheck = affine.inB === 0
      ? t.proofInvZero
      : t.proofInvMul(hex2(affine.inB), hex2(affine.inv), hex2(affine.invCheckProd));
    const rotLines = affine.rotations.map(({ shift, val }) =>
      `<div>b ≪ ${shift}  = ${bin8(val)} (${hex2(val)})</div>`
    ).join("");
    lines = `
      <div>${invCheck}</div>
      <div class="proof-head">${t.proofAffHead}</div>
      <div>b      = ${bin8(affine.inv)} (${hex2(affine.inv)})</div>
      ${rotLines}
      <div>0x63   = ${bin8(affine.constant)} (${hex2(affine.constant)})</div>
      <div><strong>XOR    = ${bin8(affine.outB)} (${hex2(affine.outB)})</strong></div>`;
  } else {
    const rotLines = affine.rotations.map(({ shift, val }) =>
      `<div>y ≪ ${shift}  = ${bin8(val)}</div>`
    ).join("");
    lines = `
      <div>${t.proofInvAffHead}</div>
      <div>y      = ${bin8(affine.inB)} (${hex2(affine.inB)})</div>
      ${rotLines}
      <div>0x05   = ${bin8(affine.constant)}</div>
      <div>XOR    = ${bin8(affine.postAff)} (${hex2(affine.postAff)}) → mod 0x11B⁻¹ = <strong>${hex2(affine.outB)} (${bin8(affine.outB)})</strong></div>`;
  }
  return `<details class="math-proof"><summary>${t.proofSummary}</summary><div class="proof-body">${lines}</div></details>`;
}

const INSPECTOR_HANDLERS = {
  input({ coord, detail, isEnc, rData }, t) {
    const nextCard = buildRoundCardSpec(detail.nextStep, rData, detail.roundIdx, isEnc);
    const noteHtml = detail.roundIdx === 0
      ? (isEnc ? t.noteEnc0 : t.noteDec0)
      : (isEnc ? (detail.hasMix ? t.noteEncMix : t.noteEncLast) : t.noteDecN);
    return {
      html: `
        <div class="explain-box">${t.explainInput(coord.r, coord.c, detail.roundIdx, nextCard ? nextCard.title : getStepLabel(detail.nextStep, isEnc))}</div>
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>${t.colVal}</th><th>Hex</th><th>${t.inspBinCol}</th></tr></thead>
            <tbody>
              <tr><td>s[${coord.r},${coord.c}] (${getStepLabel("input", isEnc)})</td><td><strong>${hex2(detail.val)}</strong></td><td>${bin8(detail.val)}</td></tr>
            </tbody>
          </table>
        </div>`,
      noteHtml,
      sboxHl: null
    };
  },

  afterSub({ detail, isEnc }, t) {
    const inHex = hex2(detail.inB);
    const outHex = hex2(detail.outB);
    return {
      html: `
        <div class="explain-box">${t.explainSub(inHex, outHex, isEnc)}</div>
        <div class="formula-box">${t.inspSubBox(inHex, detail.boxName, inHex[0], inHex[1], outHex)}</div>
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>${t.inspSubHead}</th><th>Hex</th><th>${t.inspBinCol}</th></tr></thead>
            <tbody>
              <tr><td>${t.inspSubR1}</td><td>${inHex}</td><td>${bin8(detail.inB)}</td></tr>
              <tr><td>${t.inspSubR2}</td><td>${hex2(detail.inv)}</td><td>${bin8(detail.inv)}</td></tr>
              <tr><td>${t.inspSubR3}</td><td><strong>${outHex}</strong></td><td><strong>${bin8(detail.outB)}</strong></td></tr>
            </tbody>
          </table>
        </div>
        ${renderAffineProof(detail.affine, t)}`,
      noteHtml: t.inspSubNote,
      sboxHl: detail.sboxHl
    };
  },

  afterShift({ coord, detail, isEnc }, t) {
    const dir = isEnc ? t.dirLeft : t.dirRight;
    const renderChips = (items, activeCol, clsName) => items.map((it) =>
      `<div class="shift-chip ${it.col === activeCol ? clsName : ""}"><span class="shift-chip-idx">s[${coord.r},${it.col}]</span>${hex2(it.val)}</div>`
    ).join("");
    return {
      html: `
        <div class="explain-box">${t.explainShift(coord.r, coord.c, detail.srcCol, dir)}</div>
        <div class="formula-box">${t.inspShiftBox(coord.r + 1, coord.r, dir, detail.srcCol, hex2(detail.val), coord.c)}</div>
        <div class="shift-strip"><span class="muted-note">${t.shiftBefore}</span>${renderChips(detail.beforeRow, detail.srcCol, "is-origin")}</div>
        <div class="shift-strip"><span class="muted-note">${t.shiftAfter}</span>${renderChips(detail.afterRow, coord.c, "is-dest")}</div>`,
      noteHtml: t.inspShiftNote,
      sboxHl: null
    };
  },

  afterMix({ coord, detail, isEnc }, t) {
    const termsText = [0, 1, 2, 3].map((i) => `(${hex2(detail.coeffs[i])}•${hex2(detail.colBytes[i])})`).join(" ⊕ ");
    const rows = detail.terms.map((tm) => {
      const kh = hex2(tm.k);
      const bh = hex2(tm.b);
      const ph = hex2(tm.product);
      let exp = t.mixPoly(kh, bh, ph);
      if (tm.k === 1) exp = t.mixUnit(bh);
      else if (tm.k === 2) exp = t.mixDouble(hex2(tm.shifted), tm.overflow, ph);
      else if (tm.k === 3) exp = t.mixTriple(bh, hex2(tm.x2), ph);
      return `<tr><td class="nowrap">${kh} • ${bh}</td><td>${exp}</td><td><strong>${ph}</strong></td><td>${bin8(tm.product)}</td></tr>`;
    }).join("");
    return {
      html: `
        <div class="explain-box">${t.explainMix(coord.c, isEnc)}</div>
        <div class="formula-box"><strong>${t.mixEqTitle(coord.c)}</strong> ${termsText} = <strong>${hex2(detail.outVal)}</strong></div>
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>${t.mixColMul}</th><th>${t.mixColStep}</th><th>Hex</th><th>${t.inspBinCol}</th></tr></thead>
            <tbody>
              ${rows}
              <tr><th colspan="2">${t.mixSum}</th><th>${hex2(detail.outVal)}</th><th>${bin8(detail.outVal)}</th></tr>
            </tbody>
          </table>
        </div>`,
      noteHtml: t.inspMixNote,
      sboxHl: null
    };
  },

  rk(trace, t) {
    return INSPECTOR_HANDLERS.afterKey(trace, t);
  },

  afterKey({ coord, detail }, t) {
    const explainMsg = detail.kind === "rk"
      ? t.explainRk(coord.r, coord.c, detail.wi)
      : t.explainKey(coord.r, coord.c, detail.wi, detail.round);
    const rkChips = detail.wordBytes.map((wb, rowIdx) =>
      `<span class="rk-byte ${rowIdx === coord.r ? "is-active-key" : ""}">${hex2(wb)}</span>`
    ).join("");
    return {
      html: `
        <div class="explain-box">${explainMsg}</div>
        <div class="rk-mini-strip">
          <div class="rk-bytes">
            <span class="rk-strip-label">${t.rkStripLabel(detail.wi, coord.r)}</span>
            ${rkChips}
          </div>
          <button type="button" class="compact-btn jump-btn" data-jump-word="${detail.wi}">${t.jumpWordBtn(detail.wi)}</button>
        </div>
        <div class="formula-box">${t.inspKeyBox}</div>
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>${t.colVal}</th><th>Hex</th><th>${t.inspBinCol}</th></tr></thead>
            <tbody>
              <tr><td>${t.inspKeyR1(coord.r, coord.c)}</td><td>${hex2(detail.a)}</td><td>${bin8(detail.a)}</td></tr>
              <tr><td>${t.inspKeyR2(coord.r, coord.c)}</td><td>${hex2(detail.k)}</td><td>${bin8(detail.k)}</td></tr>
              <tr><th>${t.inspKeyRes(hex2(detail.a), hex2(detail.k))}</th><th>${hex2(detail.res)}</th><th>${bin8(detail.res)}</th></tr>
            </tbody>
          </table>
        </div>`,
      noteHtml: t.inspKeyNote,
      sboxHl: null
    };
  }
};

function renderSBox(hl) {
  const t = getDict();
  const isInv = hl ? hl.inv : (APP.tab === "dec");
  const tbl = isInv ? TABLES.invSbox : TABLES.sbox;
  const hitR = hl ? (hl.byte >> 4) : -1;
  const hitC = hl ? (hl.byte & 0x0f) : -1;

  byId("sbox-title").textContent = isInv ? t.invSboxTitle : t.sboxTitle;

  let h = `<table class="sbox-table"><thead><tr><th></th>`;
  for (let c = 0; c < 16; c++) h += `<th>${c.toString(16).toUpperCase()}</th>`;
  h += `</tr></thead><tbody>`;
  for (let r = 0; r < 16; r++) {
    h += `<tr><th>${r.toString(16).toUpperCase()}</th>`;
    for (let c = 0; c < 16; c++) {
      const pinKey = `sbox:${isInv ? 1 : 0}:${r}:${c}`;
      const isPin = APP.pins.has(pinKey);
      const cls = [
        (r === hitR && c === hitC) ? "hit" : (r === hitR || c === hitC ? "rc-hl" : ""),
        isPin ? "pinned" : ""
      ].filter(Boolean).join(" ");
      h += `<td tabindex="0" role="button" aria-pressed="${isPin}" class="${cls}" data-sbox-pin="${pinKey}">${hex2(tbl[r * 16 + c])}</td>`;
    }
    h += `</tr>`;
  }
  h += `</tbody></table>`;
  byId("sbox-grid").innerHTML = h;
}

function renderRoundsTab() {
  const t = getDict();
  const isEnc = APP.tab === "enc";
  const r1 = isEnc ? APP.enc1[APP.roundIdx] : APP.dec1[APP.roundIdx];
  const r2 = isEnc ? APP.enc2[APP.roundIdx] : null;
  APP.stepKey = normalizeStepKey(APP.roundIdx, APP.stepKey, isEnc);

  const hasMix = Boolean(r1.afterMix);
  const guide = byId("round-guide");
  const roundNote = byId("round-note-body");

  if (APP.roundIdx === 0) {
    guide.innerHTML = isEnc ? t.guideEnc0 : t.guideDec0;
    roundNote.innerHTML = isEnc ? t.noteEnc0 : t.noteDec0;
  } else if (isEnc) {
    guide.innerHTML = t.guideEncN(r1.round, hasMix);
    roundNote.innerHTML = hasMix ? t.noteEncMix : t.noteEncLast;
  } else {
    guide.innerHTML = t.guideDecN(r1.round, hasMix);
    roundNote.innerHTML = t.noteDecN;
  }

  const dep = computeDependencies(APP.stepKey, APP.cellIdx, APP.roundIdx, isEnc);
  const steps = getRoundSteps(APP.roundIdx, isEnc);
  byId("matrices-grid").innerHTML = steps.map((stepKey) => {
    const spec = buildRoundCardSpec(stepKey, r1, APP.roundIdx, isEnc);
    return buildStateCard(spec.title, spec.desc, r1[stepKey], r2 ? r2[stepKey] : null, stepKey, dep);
  }).join("");

  const trace = computeCellTrace({
    rData: r1,
    step: APP.stepKey,
    idx: APP.cellIdx,
    roundIdx: APP.roundIdx,
    isEnc,
    keyData: APP.keyData
  });
  trace.isEnc = isEnc;
  trace.rData = r1;

  byId("insp-coord").textContent = t.inspCoord(trace.coord.r, trace.coord.c, trace.coord.idx + 1, getStepLabel(trace.step, isEnc));
  const out = INSPECTOR_HANDLERS[trace.detail.kind](trace, t);
  byId("insp-content").innerHTML = out.html;
  byId("insp-note-body").innerHTML = out.noteHtml;
  renderSBox(out.sboxHl);
}

function renderKeyTab() {
  const t = getDict();
  const { W, logs, roundKeys } = APP.keyData;
  const activeLog = logs[APP.wordIdx];
  const srcSet = new Set();
  const keySet = new Set();
  if (activeLog.type !== "init") {
    srcSet.add(APP.wordIdx - 1);
    keySet.add(APP.wordIdx - 4);
  }

  let tbl = `<table class="data-table data-table-compact"><thead><tr>`;
  t.keyTabCols.forEach((h) => { tbl += `<th>${h}</th>`; });
  tbl += `</tr></thead><tbody>`;
  for (let r = 0; r <= CONSTANTS.ROUNDS; r++) {
    tbl += `<tr><th>${t.keyRoundLbl(r)}</th>`;
    for (let c = 0; c < 4; c++) {
      const wi = r * 4 + c;
      const cls = [
        wi === APP.wordIdx ? "active" : "",
        srcSet.has(wi) ? "src-word" : "",
        keySet.has(wi) ? "key-word" : "",
        APP.pins.has(`key:${wi}`) ? "pinned" : ""
      ].filter(Boolean).join(" ");
      tbl += `<td><button type="button" class="w-btn ${cls}" data-w="${wi}">W[${wi}]: ${W[wi].map(hex2).join("")}</button></td>`;
    }
    const rkFirst = roundKeys[r].slice(0, 8).map(hex2).join(" ");
    const rkSecond = roundKeys[r].slice(8, 16).map(hex2).join(" ");
    tbl += `<td class="key-cell-mono"><div class="key-hex-line"><span>${rkFirst}</span><span>${rkSecond}</span></div></td></tr>`;
  }
  tbl += `</tbody></table>`;
  byId("key-schedule-table").innerHTML = tbl;

  const out = byId("key-insp-content");
  byId("key-insp-title").textContent = t.keyInspTitle(APP.wordIdx);
  const prevIdx = activeLog.i - 1;
  const prev4Idx = activeLog.i - 4;

  if (activeLog.type === "init") {
    out.innerHTML = `
      <div class="explain-box">${t.keyExplainInit(activeLog.i)}</div>
      <div class="formula-box">${t.keyInitBox(activeLog.i, hexStr(activeLog.word))}</div>`;
  } else if (activeLog.type === "rot") {
    const rconIdx = activeLog.i / 4;
    out.innerHTML = `
      <div class="explain-box">${t.keyExplainRot(activeLog.i, prevIdx, prev4Idx)}</div>
      <div class="formula-box">${t.keyRotBox(activeLog.i, prevIdx, prev4Idx, rconIdx)}</div>
      <div class="table-scroll">
        <table class="data-table">
          <tbody>
            <tr><th>${t.keyRotR1(prevIdx)}</th><td class="nowrap">${hexStr(activeLog.prev)}</td></tr>
            <tr><th>${t.keyRotR2}</th><td class="nowrap">${hexStr(activeLog.rot)}</td></tr>
            <tr><th>${t.keyRotR3}</th><td class="nowrap">${hexStr(activeLog.sub)}</td></tr>
            <tr><th>${t.keyRotR4(rconIdx, hex2(activeLog.rc))}</th><td class="nowrap">${hexStr(activeLog.rconXor)}</td></tr>
            <tr><th>${t.keyRotR5(prev4Idx)}</th><td class="nowrap">${hexStr(activeLog.prev4)}</td></tr>
            <tr><th>${t.keyRotR6(activeLog.i)}</th><td class="nowrap"><strong>${hexStr(activeLog.word)}</strong></td></tr>
          </tbody>
        </table>
      </div>`;
  } else {
    out.innerHTML = `
      <div class="explain-box">${t.keyExplainXor(prevIdx, prev4Idx)}</div>
      <div class="formula-box">${t.keyXorBox(activeLog.i, prevIdx, prev4Idx)}</div>
      <div class="table-scroll">
        <table class="data-table">
          <tbody>
            <tr><th>${t.keyXorR1(prev4Idx)}</th><td class="nowrap">${hexStr(activeLog.prev4)}</td></tr>
            <tr><th>${t.keyXorR2(prevIdx)}</th><td class="nowrap">${hexStr(activeLog.prev)}</td></tr>
            <tr><th>${t.keyXorR3(activeLog.i)}</th><td class="nowrap"><strong>${hexStr(activeLog.word)}</strong></td></tr>
          </tbody>
        </table>
      </div>`;
  }
}

function syncPresenterNotes() {
  const t = getDict();
  document.querySelectorAll(".presenter-note[data-note-id]").forEach((det) => {
    const want = APP.notesOpen.has(det.dataset.noteId);
    if (det.open !== want) det.open = want;
  });
  const btn = byId("toggle-notes-btn");
  if (btn) {
    const activeNotes = Array.from(document.querySelectorAll(".tab-panel.active .presenter-note[data-note-id]"));
    const anyClosed = activeNotes.some((d) => !APP.notesOpen.has(d.dataset.noteId));
    btn.textContent = anyClosed ? t.notesOpenAll : t.notesCloseAll;
  }
}

function toggleActiveTabNotes() {
  const activeNotes = Array.from(document.querySelectorAll(".tab-panel.active .presenter-note[data-note-id]"));
  const shouldOpen = activeNotes.some((d) => !APP.notesOpen.has(d.dataset.noteId));
  activeNotes.forEach((d) => {
    if (shouldOpen) APP.notesOpen.add(d.dataset.noteId);
    else APP.notesOpen.delete(d.dataset.noteId);
  });
  syncPresenterNotes();
}

function renderCurrentTab() {
  byId("tab-prep").classList.toggle("active", APP.tab === "prep");
  byId("tab-rounds").classList.toggle("active", APP.tab === "enc" || APP.tab === "dec");
  byId("tab-key").classList.toggle("active", APP.tab === "key");

  if (APP.tab === "prep") renderPrepTab();
  else if (APP.tab === "key") renderKeyTab();
  else renderRoundsTab();

  syncPresenterNotes();
}

function setRound(roundIdx) {
  APP.roundIdx = Math.min(Math.max(roundIdx, 0), CONSTANTS.ROUNDS);
  APP.stepKey = normalizeStepKey(APP.roundIdx, APP.stepKey, APP.tab === "enc");
  renderRoundButtons();
  renderRoundsTab();
}

function activateTabFromNav(tabName) {
  if (tabName === "enc" || tabName === "dec") {
    APP.roundIdx = 1;
    APP.stepKey = normalizeStepKey(1, null, tabName === "enc");
  }
  switchTab(tabName);
}

function switchTab(tabName) {
  APP.tab = WORKBENCH_TABS.includes(tabName) ? tabName : "prep";
  document.querySelectorAll(".tab-btn").forEach((b) => {
    const isAct = b.dataset.tab === APP.tab;
    b.classList.toggle("active", isAct);
    b.setAttribute("aria-selected", String(isAct));
  });
  const roundsPanel = byId("tab-rounds");
  if (roundsPanel) {
    roundsPanel.setAttribute("aria-labelledby", APP.tab === "dec" ? "tab-btn-dec" : "tab-btn-enc");
  }
  if (APP.tab === "enc" || APP.tab === "dec") {
    APP.stepKey = normalizeStepKey(APP.roundIdx, APP.stepKey, APP.tab === "enc");
  }
  renderRoundButtons();
  renderCurrentTab();
}

function syncSlidesHref() {
  const slidesLink = byId("slides-link");
  if (!slidesLink) return;
  const theme = document.documentElement.getAttribute("data-theme") || "dark";
  slidesLink.href = Prefs.buildHref("sunum.html", { lang: APP.lang, theme });
}

function applyTheme(theme) {
  const clean = Prefs.applyTheme(theme);
  const t = getDict();
  const label = byId("theme-btn-label");
  if (label) label.textContent = clean === "dark" ? t.themeLight : t.themeDark;
  const btn = byId("theme-btn");
  if (btn) btn.setAttribute("aria-pressed", String(clean === "light"));
  syncSlidesHref();
}

function applyPresentMode(on) {
  APP.presentMode = on;
  document.documentElement.setAttribute("data-present", on ? "true" : "false");
  Prefs.writeStorage(Prefs.STORAGE_KEYS.present, on ? "true" : "false");
  const btn = byId("present-btn");
  if (btn) btn.setAttribute("aria-pressed", String(on));
}

function applyMarkerMode(on) {
  APP.markerMode = on;
  document.documentElement.setAttribute("data-marker-mode", on ? "true" : "false");
  const btn = byId("marker-btn");
  if (btn) btn.setAttribute("aria-pressed", String(on));
}

function applyLanguage(lang, rerender = true) {
  APP.lang = Prefs.syncLangControls(lang);
  const t = getDict();
  document.title = t.pageTitle;

  STATIC_TEXT_BINDINGS.forEach(([id, key]) => {
    const el = byId(id);
    if (el) el.textContent = t[key];
  });
  STATIC_HTML_BINDINGS.forEach(([id, key]) => {
    const el = byId(id);
    if (el) el.innerHTML = t[key];
  });

  document.querySelectorAll(".note-title").forEach((el) => { el.textContent = t.noteTitle; });
  const markerBtn = byId("marker-btn");
  if (markerBtn) markerBtn.title = t.markerTitle;
  const nav = byId("main-nav");
  if (nav) nav.setAttribute("aria-label", t.navAria);
  const sboxTitle = byId("sbox-title");
  if (sboxTitle) sboxTitle.textContent = APP.tab === "dec" ? t.invSboxTitle : t.sboxTitle;

  const curTheme = document.documentElement.getAttribute("data-theme") || "dark";
  const themeLbl = byId("theme-btn-label");
  if (themeLbl) themeLbl.textContent = curTheme === "dark" ? t.themeLight : t.themeDark;
  syncSlidesHref();

  if (rerender && APP.pt1.length) syncDerivedUi();
}

function bindActivateDelegation(container, selector, handler) {
  container.addEventListener("click", (e) => {
    const target = e.target.closest(selector);
    if (target) handler(target, e);
  });
  container.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const target = e.target.closest(selector);
    if (!target) return;
    e.preventDefault();
    handler(target, e);
  });
}

function bindEvents() {
  document.querySelectorAll(".lang-btn").forEach((btn) => {
    btn.addEventListener("click", () => applyLanguage(btn.dataset.lang, true));
  });

  byId("theme-btn").addEventListener("click", () => Prefs.toggleRootTheme(applyTheme));
  byId("present-btn").addEventListener("click", () => applyPresentMode(!APP.presentMode));
  byId("marker-btn").addEventListener("click", () => applyMarkerMode(!APP.markerMode));
  byId("clear-pins-btn").addEventListener("click", () => {
    APP.pins.clear();
    syncPinCounter();
    renderCurrentTab();
  });
  byId("toggle-notes-btn").addEventListener("click", toggleActiveTabNotes);

  document.querySelectorAll(".presenter-note[data-note-id]").forEach((det) => {
    det.addEventListener("toggle", () => {
      const id = det.dataset.noteId;
      if (det.open) APP.notesOpen.add(id);
      else APP.notesOpen.delete(id);
      syncPresenterNotes();
    });
  });

  ["pt1-input", "pt2-input", "key-input"].forEach((id) => byId(id).addEventListener("input", () => updateAll(true)));
  byId("pad-select").addEventListener("change", () => updateAll(true));
  byId("show-diff-chk").addEventListener("change", (e) => {
    APP.showDiff = e.target.checked;
    renderRoundsTab();
  });

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => activateTabFromNav(btn.dataset.tab));
  });

  bindActivateDelegation(byId("prep-content"), "[data-prep-idx]", (target, e) => {
    const idx = parseInt(target.dataset.prepIdx, 10);
    if (APP.markerMode || e.shiftKey) togglePin(`prep:${idx}`);
    else {
      APP.prepCellIdx = idx;
      renderPrepTab();
    }
  });

  byId("round-buttons").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-r]");
    if (btn) setRound(parseInt(btn.dataset.r, 10));
  });

  bindActivateDelegation(byId("matrices-grid"), "td[data-step]", (cellEl, e) => {
    const step = cellEl.dataset.step;
    const idx = parseInt(cellEl.dataset.idx, 10);
    if (APP.markerMode || e.shiftKey) {
      togglePin(`${APP.tab}:${APP.roundIdx}:${step}:${idx}`);
    } else {
      APP.stepKey = step;
      APP.cellIdx = idx;
      renderRoundsTab();
    }
  });

  byId("insp-content").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-jump-word]");
    if (!btn) return;
    APP.wordIdx = parseInt(btn.dataset.jumpWord, 10);
    switchTab("key");
  });

  bindActivateDelegation(byId("sbox-grid"), "td[data-sbox-pin]", (cell) => {
    togglePin(cell.dataset.sboxPin);
  });

  byId("key-schedule-table").addEventListener("click", (e) => {
    const btn = e.target.closest(".w-btn[data-w]");
    if (!btn) return;
    const wi = parseInt(btn.dataset.w, 10);
    if (APP.markerMode || e.shiftKey) togglePin(`key:${wi}`);
    else {
      APP.wordIdx = wi;
      renderKeyTab();
    }
  });

  document.addEventListener("keydown", (e) => {
    const tag = e.target && e.target.tagName;
    if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    const tabIdx = ["1", "2", "3", "4"].indexOf(e.key);
    if (tabIdx !== -1) {
      activateTabFromNav(WORKBENCH_TABS[tabIdx]);
      return;
    }

    const low = e.key.toLowerCase();
    if (low === "t") Prefs.toggleRootTheme(applyTheme);
    else if (low === "p") applyPresentMode(!APP.presentMode);
    else if (low === "h") applyMarkerMode(!APP.markerMode);
    else if (low === "n") toggleActiveTabNotes();
    else if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      const delta = e.key === "ArrowRight" ? 1 : -1;
      if (APP.tab === "enc" || APP.tab === "dec") {
        const nextRound = APP.roundIdx + delta;
        if (nextRound >= 0 && nextRound <= CONSTANTS.ROUNDS) setRound(nextRound);
      } else if (APP.tab === "key") {
        const nextWord = APP.wordIdx + delta;
        if (nextWord >= 0 && nextWord < CONSTANTS.WORDS) {
          APP.wordIdx = nextWord;
          renderKeyTab();
        }
      }
    }
  });
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    const boot = Prefs.readBootPrefs(window.location.search);
    const qTab = boot.params.get("tab");
    if (qTab && WORKBENCH_TABS.includes(qTab)) {
      APP.tab = qTab;
      const qRound = parseInt(boot.params.get("round"), 10);
      if (!Number.isNaN(qRound) && qRound >= 0 && qRound <= CONSTANTS.ROUNDS && (qTab === "enc" || qTab === "dec")) {
        APP.roundIdx = qRound;
      }
      if (qTab === "enc" || qTab === "dec") {
        APP.stepKey = normalizeStepKey(APP.roundIdx, boot.params.get("step"), qTab === "enc");
      }
      const qCell = parseInt(boot.params.get("cell"), 10);
      if (!Number.isNaN(qCell) && qCell >= 0 && qCell < 16) {
        APP.cellIdx = qCell;
      }
    }

    Prefs.applyTheme(boot.theme);
    applyLanguage(boot.lang, false);
    const themeBtn = byId("theme-btn");
    if (themeBtn) themeBtn.setAttribute("aria-pressed", String(boot.theme === "light"));
    applyPresentMode(boot.present);
    applyMarkerMode(false);
    syncPinCounter();
    bindEvents();
    updateAll(false);
    updateFieldHints();
    const toggleText = byId("diff-toggle-text");
    if (toggleText) toggleText.innerHTML = getDict().diffToggle(escapeHtml(APP.pt2Str || '""'));
    renderBanner();
    switchTab(APP.tab);
  });
}

if (typeof module === "object" && module.exports) {
  module.exports = {
    WORKBENCH_TABS,
    I18N,
    APP,
    escapeHtml,
    buildRoundCardSpec,
    updateAll,
    renderBanner,
    renderPrepTab
  };
}
