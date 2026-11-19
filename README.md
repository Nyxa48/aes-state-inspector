# AES-State-Inspector

[ English ](#english) &nbsp;&middot;&nbsp; [ Türkçe ](#turkce)

---

<h2 id="english">English</h2>

**AES-State-Inspector** is a zero-dependency interactive cryptographic workbench and classroom presentation tool that implements **FIPS-197 (Advanced Encryption Standard — Rijndael)** from scratch in pure JavaScript.

Rather than relying on external crypto APIs, every $GF(2^8)$ multiplication, S-Box algebraic construction, 44-word Key Schedule expansion, and inverse cipher transformation runs live in the browser with step-by-step inspection. Both the interactive workbench ([index.html](index.html)) and the 10-slide presentation deck ([sunum.html](sunum.html)) support instant **TR / EN** language switching, **Dark / Light (Projector)** themes, and keyboard navigation.

### How AES-128 Works (Step-by-Step Guide)

#### 1. Step 0 — Padding & Column-Major State Matrix
AES-128 always encrypts fixed **16-byte (128-bit)** blocks arranged as a $4 \times 4$ **state matrix**. Shorter inputs are padded using either `0x00` zero padding (for clear walkthroughs) or `PKCS#7` (filling $N$ missing bytes with the byte value $N$, or a full 16 bytes of `0x10` when the input is already 16 bytes).

A common source of confusion is byte ordering: AES populates the $4 \times 4$ matrix **column by column (column-major)**, not row by row. For `"ARABA"` (`41 52 41 42 41`) vs `"ARABB"` (`41 52 41 42 42`):

| Row \ Col | Col 0 (`s[r,0]`) | Col 1 (`s[r,1]`) | Col 2 (`s[r,2]`) | Col 3 (`s[r,3]`) |
| --- | --- | --- | --- | --- |
| **Row 0** | `41` (`A`) | `41` ≠ `42` (`A` vs `B`) | `00` | `00` |
| **Row 1** | `52` (`R`) | `00` | `00` | `00` |
| **Row 2** | `41` (`A`) | `00` | `00` | `00` |
| **Row 3** | `42` (`B`) | `00` | `00` | `00` |

`0x41` (`01000001`) and `0x42` (`01000010`) differ by **only 2 bits** in Byte 5 (`s[0,1]`).

#### 2. Key Expansion (`W[0]..W[43]`)
AES-128 runs **Round 0** (initial key whitening) plus **10 cipher rounds**, requiring **11 round keys** (44 32-bit column words `W[0]..W[43]`):
- `W[0]..W[3]` are copied directly from the 128-bit cipher key.
- If `i % 4 !== 0`: `W[i] = W[i - 4] ⊕ W[i - 1]`.
- If `i % 4 === 0`: `W[i] = W[i - 4] ⊕ SubWord(RotWord(W[i - 1])) ⊕ Rcon[i / 4]`, where `RotWord` rotates 1 byte left, `SubWord` applies the S-Box, and `Rcon` breaks inter-round symmetry.

Worked trace for `W[4]` with the FIPS-197 key `2B7E1516 28AED2A6 ABF71588 09CF4F3C`:
1. `W[3]` = `09 CF 4F 3C`
2. `RotWord(W[3])` = `CF 4F 3C 09`
3. `SubWord` = `8A 84 EB 01`
4. `⊕ Rcon[1] (01 00 00 00)` = `8B 84 EB 01`
5. `⊕ W[0] (2B 7E 15 16)` = **`A0 FA FE 17`** (`W[4]`)

#### 3. Inside Each Encryption Round (Rounds 1–10)
1. **SubBytes (Confusion):** Non-linear byte substitution over $GF(2^8)$ modulo the irreducible polynomial $m(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`). Each byte takes its multiplicative inverse (with `0x00 → 0x00`), then an affine matrix transform + XOR `0x63` to eliminate fixed points. Example from Round 1 `s[0,0]`: `0x6A` (`01101010`) → inverse `0x91` (`10010001`) → affine + `0x63` = **`0x02`** (S-Box row `6`, col `A`).
2. **ShiftRows (Cross-Column Mixing):** Row `r` rotates left by `r` bytes (`0, 1, 2, 3`). Without this step, columns would never interact.
3. **MixColumns (Diffusion):** Each column is multiplied by the fixed MDS matrix `[[02,03,01,01],[01,02,03,01],[01,01,02,03],[03,01,01,02]]` in $GF(2^8)$:
   - `0x01 • b = b`
   - `0x02 • b` (`xtime`): left-shift `b` by 1 bit; if the most significant bit (`MSB = 1`) overflows 8 bits, reduce modulo `0x11B` by XORing the lower 8 bits with **`0x1B`**.
   - `0x03 • b = (0x02 • b) ⊕ b`
   - *Why is `MixColumns` omitted in Round 10?* Because no key addition follows Round 10, a linear matrix layer could be inverted without knowing the key; omitting it adds zero weakness and keeps encryption and decryption symmetric.
4. **AddRoundKey (Key Mixing):** Bitwise XOR with the round key (`(A ⊕ K) ⊕ K = A`). Constant-time and self-inverting.

#### 4. Live Avalanche Effect (`ARABA` vs `ARABB`)
Starting from a **2-bit** difference in Byte 5 (`s[0,1]`), here is how AES-128 diffuses the change across all 10 rounds:

| Stage | Changed Bytes | Flipped Bits | Ratio |
| --- | --- | --- | --- |
| Initial (Round 0) | 1 / 16 | 2 / 128 | 1.6% |
| End of Round 1 (`MixColumns` spreads Col 1) | 4 / 16 | 23 / 128 | 18.0% |
| End of Round 2 (`ShiftRows` + `MixColumns` hit all cols) | 16 / 16 | 71 / 128 | 55.5% |
| End of Round 3 | 16 / 16 | 66 / 128 | 51.6% |
| End of Round 4 | 16 / 16 | 66 / 128 | 51.6% |
| End of Round 5 | 15 / 16 | 58 / 128 | 45.3% |
| End of Round 6 | 16 / 16 | 60 / 128 | 46.9% |
| End of Round 7 | 16 / 16 | 65 / 128 | 50.8% |
| End of Round 8 | 16 / 16 | 58 / 128 | 45.3% |
| End of Round 9 | 16 / 16 | 72 / 128 | 56.3% |
| **End of Round 10 (Ciphertext)** | **16 / 16** | **65 / 128** | **50.8%** |

#### 5. Decryption Pipeline
Decryption starts with `AddRoundKey(K10)` and applies the inverse operations in reverse order for Rounds 9 down to 0: `InvShiftRows` (shift right `0, 1, 2, 3`) → `InvSubBytes` (inverse S-Box) → `AddRoundKey` → `InvMixColumns` (for Rounds 9..1, using the inverse MDS matrix `{0E, 0B, 0D, 09}`), recovering the exact original plaintext byte for byte.

### Verification Vectors

- **Default Classroom Vector (`ARABA`):**
  - Plaintext: `41 52 41 42 41 00 00 00 00 00 00 00 00 00 00 00`
  - Key: `2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C`
  - Round 10 Ciphertext: `EA 38 5F A9 15 11 6B 6D 7C 3A EB A0 1F A0 0C C4`
- **NIST FIPS-197 Appendix B Vector:**
  - Plaintext: `3243F6A8885A308D313198A2E0370734`
  - Key: `2B7E151628AED2A6ABF7158809CF4F3C`
  - Ciphertext: `39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32`

### Keyboard Shortcuts & Presentation Mode

- **`1`–`4`:** Switch tabs (`Step 0`, `Encryption`, `Key Schedule`, `Decryption`)
- **`←` / `→`:** Step through Rounds `0–10` (or words `W[0]..W[43]`, or slides in `sunum.html`)
- **`P`:** Toggle Presentation Mode (larger projector typography & shortcut bar)
- **`T`:** Toggle Dark / Light (Projector) theme
- **`N`:** Toggle collapsible Speaker Notes (`Sunum Notu` / `Speaker Note`)

---

<h2 id="turkce">Türkçe</h2>

**AES-State-Inspector**, **FIPS-197 (Advanced Encryption Standard — Rijndael)** standardını bit ve bayt düzeyinde sıfırdan gerçekleyen, harici kütüphane bağımlılığı olmayan etkileşimli bir kriptoloji laboratuvarı ve sunum aracıdır.

Tüm $GF(2^8)$ sonlu cisim çarpımları, S-Box üretim adımları, 44 kelimelik anahtar türetme (Key Schedule) ve ters deşifreleme adımları tarayıcıda saf JavaScript ile hesaplanır. Hem ana laboratuvar ([index.html](index.html)) hem de 10 slaytlık sunum ([sunum.html](sunum.html)) **TR / EN** dil değişimi, **Koyu / Açık (Projeksiyon)** tema ve klavye kısayollarını destekler.

### AES-128 Nasıl Çalışır? (Adım Adım Öğretici Özet)

#### 1. Adım 0 — Blok Dolgusu ve Sütun-Öncelikli Durum Matrisi
AES-128 veriyi her zaman **16 baytlık (128 bit)** sabit bloklar hâlinde ve $4 \times 4$ **durum (state) matrisi** olarak işler. 16 bayttan kısa girdiler sıfır dolgusu (`0x00`) veya eksik bayt sayısı kadar aynı dolgu değerinin yazıldığı `PKCS#7` ile 16 bayta tamamlanır.

En sık karıştırılan nokta yerleşim sırasıdır: Baytlar matrise satır satır değil **sütun sütun (yukarıdan aşağıya)** yerleştirilir. `ARABA` (`41 52 41 42 41`) ve `ARABB` (`41 52 41 42 42`) karşılaştırmasında:

| Satır \ Sütun | 0. Sütun (`s[r,0]`) | 1. Sütun (`s[r,1]`) | 2. Sütun (`s[r,2]`) | 3. Sütun (`s[r,3]`) |
| --- | --- | --- | --- | --- |
| **0. Satır** | `41` (`A`) | `41` ≠ `42` (`A` vs `B`) | `00` | `00` |
| **1. Satır** | `52` (`R`) | `00` | `00` | `00` |
| **2. Satır** | `41` (`A`) | `00` | `00` | `00` |
| **3. Satır** | `42` (`B`) | `00` | `00` | `00` |

`0x41` (`01000001`) ile `0x42` (`01000010`) arasında yalnızca 5. baytta (`s[0,1]`) **2 bit** fark vardır.

#### 2. Anahtar Genişletme (`W[0]..W[43]`)
Başlangıç adımı (Tur 0) ve 10 şifreleme turu için **11 tur anahtarı** (44 adet 32-bit sütun kelimesi `W[0]..W[43]`) türetilir:
- `W[0]..W[3]` doğrudan 128-bit başlangıç anahtarından alınır.
- `i % 4 !== 0` ise: `W[i] = W[i - 4] ⊕ W[i - 1]`.
- `i % 4 === 0` ise: `W[i] = W[i - 4] ⊕ SubWord(RotWord(W[i - 1])) ⊕ Rcon[i / 4]`.

`2B7E1516 28AED2A6 ABF71588 09CF4F3C` anahtarı için `W[4]` hesabı:
1. `W[3]` = `09 CF 4F 3C`
2. `RotWord(W[3])` = `CF 4F 3C 09` (1 bayt sola döndürme)
3. `SubWord` = `8A 84 EB 01` (S-Box dönüşümü)
4. `⊕ Rcon[1] (01 00 00 00)` = `8B 84 EB 01`
5. `⊕ W[0] (2B 7E 15 16)` = **`A0 FA FE 17`** (`W[4]`)

#### 3. Bir Şifreleme Turunun 4 Adımı (Tur 1–10)
1. **SubBytes (Karışıklık / Confusion):** Her bayt $m(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`) indirgenemez polinomu modunda $GF(2^8)$ çarpımsal tersine çevrilir (`0x00 → 0x00`), ardından sabit noktaları önlemek için afin dönüşüm + `0x63` XOR uygulanır. Örnek (Tur 1 `s[0,0]`): `0x6A` → tersi `0x91` → afin + `0x63` = **`0x02`** (S-Box 6. satır, A sütunu).
2. **ShiftRows (Sütunlar Arası Geçiş):** `r.` satır `r` birim (`0, 1, 2, 3`) sola kaydırılır; böylece sütunlar birbirinden bağımsız kalmaz.
3. **MixColumns (Yayılma / Diffusion):** Her sütun `[[02,03,01,01],[01,02,03,01],[01,01,02,03],[03,01,01,02]]` MDS matrisiyle $GF(2^8)$ üzerinde çarpılır:
   - `0x01 • b = b`
   - `0x02 • b` (`xtime`): 1 bit sola kaydırılır; en soldaki bit (`MSB = 1`) 8 bitten taşarsa `0x11B` indirgemesi için alt 8 bit **`0x1B`** ile XOR'lanır.
   - `0x03 • b = (0x02 • b) ⊕ b`
   - *10. turda neden MixColumns yok?* Sonrasında başka anahtar eklenmediği için doğrusal olan `MixColumns` anahtar bilinmeden geri çevrilebilirdi; çıkarılması şifreleme ile deşifrelemeyi simetrik tutar.
4. **AddRoundKey (Anahtar Mühürleme):** Durum matrisi o turun anahtarıyla bit bazında XOR'lanır (`(A ⊕ K) ⊕ K = A`).

#### 4. Canlı Çığ Etkisi (`ARABA` vs `ARABB`)
Başlangıçtaki **2 bitlik** farkın 10 tur boyunca tüm matrise yayılması:

| Aşama | Değişen Bayt | Değişen Bit | Oran |
| --- | --- | --- | --- |
| Başlangıç (Tur 0) | 1 / 16 | 2 / 128 | %1.6 |
| Tur 1 Sonu (`MixColumns` 1. sütunu etkiler) | 4 / 16 | 23 / 128 | %18.0 |
| Tur 2 Sonu (`ShiftRows` + `MixColumns` tüm bloğa yayar) | 16 / 16 | 71 / 128 | %55.5 |
| Tur 3 Sonu | 16 / 16 | 66 / 128 | %51.6 |
| Tur 4 Sonu | 16 / 16 | 66 / 128 | %51.6 |
| Tur 5 Sonu | 15 / 16 | 58 / 128 | %45.3 |
| Tur 6 Sonu | 16 / 16 | 60 / 128 | %46.9 |
| Tur 7 Sonu | 16 / 16 | 65 / 128 | %50.8 |
| Tur 8 Sonu | 16 / 16 | 58 / 128 | %45.3 |
| Tur 9 Sonu | 16 / 16 | 72 / 128 | %56.3 |
| **Tur 10 Sonu (Şifreli Çıktı)** | **16 / 16** | **65 / 128** | **%50.8** |

#### 5. Deşifreleme (Ters Dönüşüm)
`AddRoundKey(K10)` ile başlar; ardından 9'dan 0'a her turda ters adımlar uygulanır: `InvShiftRows` (sağa `0, 1, 2, 3`) → `InvSubBytes` → `AddRoundKey` → `InvMixColumns` (Tur 9..1 için ters `{0E, 0B, 0D, 09}` matrisi).

### Doğrulama Vektörleri

- **Varsayılan Sunum Vektörü (`ARABA`):**
  - Düz Metin: `41 52 41 42 41 00 00 00 00 00 00 00 00 00 00 00`
  - Anahtar: `2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C`
  - Tur 10 Çıktısı: `EA 38 5F A9 15 11 6B 6D 7C 3A EB A0 1F A0 0C C4`
- **NIST FIPS-197 Appendix B Vektörü:**
  - Düz Metin: `3243F6A8885A308D313198A2E0370734`
  - Anahtar: `2B7E151628AED2A6ABF7158809CF4F3C`
  - Çıktı: `39 25 84 1D 02 DC 09 FB DC 11 85 97 19 6A 0B 32`

### Klavye Kısayolları ve Sunum Modu

- **`1`–`4`:** Sekmeler arası geçiş (`Adım 0`, `Şifreleme`, `Anahtar Türetme`, `Deşifreleme`)
- **`←` / `→`:** Turlar (`0–10`), kelimeler (`W[0]..W[43]`) veya `sunum.html` slaytları arası geçiş
- **`P`:** Sunum / Projeksiyon Modunu aç/kapat
- **`T`:** Koyu / Açık Tema değiştir
- **`N`:** Konuşmacı / Sunum Notlarını aç/kapat

### Proje Yapısı

```text
├── index.html          # İnteraktif AES-128 laboratuvarı (TR / EN)
├── aes.js              # Saf GF(2^8) aritmetiği, AES-128 motoru ve durum izleme çekirdeği
├── ui-prefs.js         # Ortak tema, dil, URL yönlendirme ve tarayıcı tercih yardımcısı
├── app.js              # Laboratuvar arayüzü, olay delegasyonu ve çift dil sözlüğü
├── tokens.css          # Ortak Koyu / Açık (Projeksiyon) tema değişkenleri ve temel bileşenler
├── style.css           # Laboratuvara özgü düzen ve Sunum Modu ölçeklendirmesi
├── sunum.html          # 10 slaytlık teknik AES-128 sunumu (TR / EN)
├── tarihce.html        # 5 slaytlık kısa AES tarihçesi sunumu (DES → FIPS-197, TR / EN)
├── deck.css            # Sunum desteleri için ortak 16:9 yerleşim ve bileşen stilleri
├── deck.js             # Sunum desteleri için ortak gezinme, tema ve dil denetleyicisi
├── tests/aes.test.js   # FIPS-197 vektör, çığ etkisi, adım izleme ve sözleşme testleri (`node --test`)
├── SUNUM_REHBERI.md    # Konuşmacı paylaşımı, demo adımları ve soru-cevap rehberi
└── README.md           # Çift dilli (EN/TR) öğretici proje dokümantasyonu
```
