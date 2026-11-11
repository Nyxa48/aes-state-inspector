# AES-State-Inspector

[ English ](#english) &nbsp;&middot;&nbsp; [ Türkçe ](#turkce)

---

<h2 id="english">English</h2>

**AES-State-Inspector** is a zero-dependency interactive cryptographic workbench that implements the **FIPS-197 (Advanced Encryption Standard — Rijndael)** specification at the bit and byte level in pure JavaScript.

All $GF(2^8)$ finite-field arithmetic, S-Box generation matrices, 44-word Key Schedule expansion, and inverse cipher transformations are implemented from scratch without external cryptographic libraries.

### Key Features

- **Step 0 — Block Formatting & Column-Major State Matrix**: Converts ASCII/Hex inputs, pads to 16 bytes, and populates the $4 \times 4$ state matrix in column-major order.
- **Live Avalanche Effect Comparison**: Encrypts a primary plaintext (`ARABA`) alongside a modified plaintext (`ARABB`) across all 10 rounds, highlighting how a 2-bit input difference propagates via `ShiftRows` and `MixColumns` to flip 65 of 128 bits (50.8%).
- **Interactive Cell Math Inspector**: Clicking any byte in the $4 \times 4$ matrix reveals its exact step-by-step derivation:
  - **SubBytes / InvSubBytes**: Multiplicative inverse in $GF(2^8)$ modulo $m(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`), affine matrix transformation, and $16 \times 16$ S-Box lookup coordinates.
  - **ShiftRows / InvShiftRows**: Row offset shift and previous/new byte coordinates.
  - **MixColumns / InvMixColumns**: MDS matrix multiplication, `xtime` (`0x02`) overflow reduction via XOR with `0x1B` when `MSB = 1`, and 8-bit binary addition breakdown.
  - **AddRoundKey**: Bitwise XOR between the state byte and round key byte.
- **Key Schedule (`W[0]..W[43]`)**: Full derivation of all 44 round-key words across 11 rounds, detailing `RotWord`, `SubWord`, and `Rcon` transformations on multiples of 4.
- **Full Decryption Pipeline**: Verifies round-by-round inverse recovery (`InvShiftRows`, `InvSubBytes`, `AddRoundKey`, `InvMixColumns`) back to the original plaintext.

### Default Verification Vector

- **Plaintext:** `ARABA` (`41 52 41 42 41 00 00 00 00 00 00 00 00 00 00 00`)
- **Cipher Key (FIPS-197):** `2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C`
- **Initial AddRoundKey:** `6A 2C 54 54 69 AE D2 A6 AB F7 15 88 09 CF 4F 3C`
- **Round 1 Output:** `21 2B 8C 61 7D CA CE 0D 66 8A FD 7D CA 8F 20 51`
- **Round 10 Ciphertext:** `EA 38 5F A9 15 11 6B 6D 7C 3A EB A0 1F A0 0C C4`

---

<h2 id="turkce">Türkçe</h2>

**AES-State-Inspector**, **FIPS-197 (Advanced Encryption Standard — Rijndael)** standardını bit ve bayt düzeyinde simüle etmek, hücre matematiğini doğrulamak ve çığ etkisini (avalanche effect) görselleştirmek amacıyla geliştirilmiş interaktif bir kriptoloji aracıdır.

Harici bir şifreleme kütüphanesi kullanılmamıştır; $GF(2^8)$ sonlu cisim aritmetiği, S-Box üretim matrisi, anahtar genişletme (Key Schedule) ve ters dönüşüm adımlarının tamamı saf JavaScript ile sıfırdan gerçeklenmiştir.

### Temel Özellikler

- **Adım 0 (Blok Hazırlama ve Durum Matrisi):** Düz metnin ASCII ve Hex karşılıklarını çıkarır, 16 bayta tamamlar ve AES standardına uygun olarak $4 \times 4$ durum (state) tablosuna sütun-öncelikli (column-major) dizilimle yerleştirir.
- **Canlı Çığ Etkisi (Avalanche Effect) Karşılaştırması:** Ana metin (`ARABA`) ile karşılaştırma metnini (`ARABB`) aynı anda şifreler. Girdideki 2 bitlik farkın turlar ilerledikçe `ShiftRows` ve `MixColumns` adımlarıyla tüm matrise nasıl yayıldığını ve 10. tur sonunda 128 bitin 65 bitini (%50.8) nasıl değiştirdiğini canlı olarak işaretler.
- **Hücre Matematiği Denetçisi:** Matris üzerindeki herhangi bir bayta tıklandığında o hücrenin nasıl hesaplandığını adım adım gösterir:
  - **SubBytes / InvSubBytes:** $GF(2^8)$ üzerinde $m(x) = x^8 + x^4 + x^3 + x + 1$ ($\text{0x11B}$) indirgenemez polinomuna göre çarpımsal tersini, afin dönüşümünü ve $16 \times 16$ S-Box tablosundaki satır/sütun kesişimini verir.
  - **ShiftRows / InvShiftRows:** İlgili satırın kaç birim sola veya sağa kaydığını ve baytın eski/yeni koordinatlarını gösterir.
  - **MixColumns / InvMixColumns:** Seçili sütunun sabit MDS matrisiyle çarpımını, $\text{0x02}$ (`xtime`) adımında 8 bitten taşma (MSB=1) varsa $\text{0x1B}$ ile XOR indirgemesini ve 4 terimin 8-bit ikilik (binary) alt alta toplamını tablo halinde sunar.
  - **AddRoundKey:** Durum baytı ile tur anahtarı baytının bit düzeyinde XOR işlemini gösterir.
- **Anahtar Türetme (Key Expansion):** 128-bit başlangıç anahtarından 11 tur için üretilen 44 kelimenin (`W[0]..W[43]`) tamamını listeler; `RotWord`, `SubWord` ve `Rcon` adımlarını açıklar.
- **Deşifreleme (Ters Dönüşüm):** 10. tur sonunda elde edilen şifreli metnin (`EA 38 5F A9...`) ters adımlarla (`InvShiftRows`, `InvSubBytes`, `AddRoundKey`, `InvMixColumns`) başlangıçtaki düz metne dönüşünü doğrular.

### Dosya Yapısı

```text
├── index.html   # Semantik arayüz iskeleti
├── style.css    # Koyu/Açık tema destekli tablo ve matris stilleri
├── app.js       # GF(2^8) aritmetiği, AES-128 motoru ve hücre denetçisi
└── README.md    # Proje dokümantasyonu
```
