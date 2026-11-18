# AES-128 İki Kişilik Sunum ve Canlı Demo Rehberi

Bu rehber, yarınki sınıf sunumunda **1. Konuşmacı** ve **2. Konuşmacı** arasındaki rol paylaşımını, `sunum.html` slayt akışını, `index.html` üzerindeki canlı demo adımlarını ve olası hoca sorularına verilecek kısa teknik yanıtları içerir.

> **Projeksiyon İpucu:** Sınıfta projeksiyon/akıllı tahta kontrastı soluksa hem [sunum.html](sunum.html) hem de [index.html](index.html) içinde **`T`** tuşuna basarak **Açık Tema**ya geçin. Laboratuvarda **`P`** tuşu **Sunum Modu**nu (büyük punto ve klavye çubuğu), **`N`** tuşu ise açılır-kapanır **Sunum Notu** kutularını açar.

---

## 1. Zaman Planı ve Rol Dağılımı (~8–10 Dakika)

| Bölüm | Süre | Sorumlu | Ekran |
| --- | --- | --- | --- |
| Açılış ve Genel Mimari (Slayt 1–2) | 1.5 dk | Ortak → 1. Konuşmacı | `sunum.html` |
| Adım 0 ve Anahtar Türetme (Slayt 3–4) | 2 dk | 1. Konuşmacı | `sunum.html` |
| Tur Matematiği: SubBytes, ShiftRows, MixColumns (Slayt 5–7) | 2.5 dk | 2. Konuşmacı | `sunum.html` |
| Çığ Etkisi Deneyi: `ARABA` vs `ARABB` (Slayt 8) | 1 dk | 2. Konuşmacı | `sunum.html` |
| Deşifreleme ve Kapanış Özeti (Slayt 9) | 1 dk | 1. Konuşmacı | `sunum.html` |
| Canlı Laboratuvar Demosu (Slayt 10 → `index.html`) | 2 dk | 1. ve 2. Konuşmacı sırayla | `index.html?present=1` |

---

## 2. Slayt Slayt Konuşma Akışı (`sunum.html`)

### Slayt 1 · Kapak *(Ortak — ~30 sn)*
- **1. Konuşmacı:** *"Bugün FIPS-197 standardı olan AES-128 simetrik blok şifrelemeyi ve bunu sıfırdan, hiçbir hazır kriptoloji kütüphanesi kullanmadan geliştirdiğimiz interaktif laboratuvar üzerinden anlatacağız."*
- **2. Konuşmacı:** *"Sadece teoriyi değil; tek bir baytta 2 bitlik değişimin turlar boyunca nasıl çığ etkisine dönüştüğünü adım adım canlı göstereceğiz."*

### Slayt 2 · Neden AES ve 128-Bit Yapısı *(1. Konuşmacı — ~45 sn)*
- DES'in 56-bit anahtarının kaba kuvvet saldırılarına karşı yetersiz kalmasıyla 2001'de Rijndael'in AES (FIPS-197) olarak seçildiğini belirtin.
- Feistel ağından farkını vurgulayın: her turda bloğun yarısını değil, **16 baytın tamamını (4×4 durum matrisi)** işler; AES-128'de **10 tur** çalışır.

### Slayt 3 · Adım 0: Sütun-Öncelikli Yerleşim *(1. Konuşmacı — ~1 dk)*
- `ARABA` kelimesinin ASCII karşılıklarını gösterin: `41 52 41 42 41`, kalan 11 bayt `00` ile doldurulur.
- Kritik detayı söyleyin: *"İlk 4 bayt birinci satıra değil, birinci sütuna yukarıdan aşağıya yazılır."*
- 5. bayt olan `s[0,1]` hücresinde `ARABA` (`0x41`) ile `ARABB` (`0x42`) arasında yalnızca **2 bit fark** olduğuna dikkat çekin.

### Slayt 4 · Anahtar Genişletme (`W[0]..W[43]`) *(1. Konuşmacı — ~1 dk)*
- 16 baytlık tek anahtardan başlangıç (Tur 0) dahil **11 tur** için `11 × 4 = 44` adet 32-bit kelime üretildiğini açıklayın.
- Sağdaki `W[4]` örneğini gösterin: 4'ün katı olan sütunlarda `RotWord` (1 bayt sola döndür) → `SubWord` (S-Box) → `Rcon[1]` (`01 00 00 00`) ile `XOR` → `W[0]` ile `XOR` adımlarından `A0 FA FE 17` elde edilir.
- Geçiş cümlesi: *"Şimdi bu anahtarların her turda veri matrisine nasıl uygulandığını arkadaşım anlatacak."*

### Slayt 5 · Bir AES Turunun 4 Adımı *(2. Konuşmacı — ~45 sn)*
- Tur 0'da yalnızca `AddRoundKey` yapıldığını, Tur 1–9'da **SubBytes → ShiftRows → MixColumns → AddRoundKey** sırasının uygulandığını anlatın.
- `SubBytes` katmanının **karışıklık (confusion)**, `ShiftRows` ve `MixColumns` katmanlarının ise **yayılma (diffusion)** sağladığını vurgulayın.
- 10. turda `MixColumns` neden yok? *"Son turda ek bir anahtar katmanı gelmediği için doğrusal olan MixColumns geri alınabilir; çıkarılması güvenlik kaybı yaratmaz."*

### Slayt 6 · SubBytes ve GF(2⁸) S-Box Matematiği *(2. Konuşmacı — ~1 dk)*
- S-Box değerlerinin rastgele olmadığını, $m(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`) polinomu modunda **çarpımsal ters + afin dönüşüm (`⊕ 0x63`)** ile üretildiğini anlatın.
- Sağdaki örneği okuyun: Tur 1 `s[0,0]` hücresindeki `6A` baytı önce `GF(2⁸)` tersiyle `91`'e, ardından afin dönüşümle `02`'ye dönüşür (S-Box `6. satır, A sütunu`).

### Slayt 7 · ShiftRows ve MixColumns (`0x1B` Kuralı) *(2. Konuşmacı — ~45 sn)*
- `ShiftRows`'un 0., 1., 2., 3. satırları sırasıyla 0, 1, 2, 3 kutu sola kaydırarak sütunlar arası bağımlılık kurduğunu söyleyin.
- `MixColumns`'da `0x02` (`xtime`) ile çarparken sayı 1 bit sola kaydırılır; eğer en sol bit (`MSB = 1`) 8 bitten taşarsa **`0x1B` ile XOR** indirgemesi yapılır. `03 • b` ise `(02 • b) ⊕ b` olarak hesaplanır.

### Slayt 8 · Çığ Etkisi Grafiği (`ARABA` vs `ARABB`) *(2. Konuşmacı — ~1 dk)*
- Grafik üzerinden sıçramayı gösterin:
  - **Tur 0:** 1 bayt, **2 / 128 bit (%1.6)**
  - **Tur 1 sonu:** `MixColumns` ile 1. sütundaki 4 bayta yayılır → **23 / 128 bit (%18.0)**
  - **Tur 2 sonu:** `ShiftRows` o sütunu 4 ayrı sütuna dağıtır ve `MixColumns` tüm bloğa yayar → **16 / 16 bayt, 71 / 128 bit (%55.5)**
  - **Tur 10 sonu:** **65 / 128 bit (%50.8)** — ideal kriptografik karışım.
- Geçiş cümlesi: *"Şimdi bu sürecin nasıl hatasız geri çevrildiğini ve canlı uygulamamızı görelim."*

### Slayt 9 · Deşifreleme *(1. Konuşmacı — ~45 sn)*
- Şifrelemenin tam ters sırasını söyleyin: `InvShiftRows` (sağa kaydır) → `InvSubBytes` → `AddRoundKey` (`XOR` kendi tersi) → `InvMixColumns` (`{0E, 0B, 0D, 09}` matrisi).
- `EA 38 5F A9...` çıktısının ters adım 10 sonunda tekrar `41 52 41 42 41` (`ARABA`) haline döndüğünü vurgulayın.

---

## 3. Canlı Demo Senaryosu (`index.html?present=1`)

Slayt 10'daki kartlara tıklayarak veya tarayıcı sekmesinden `index.html` sayfasına geçerek şu 4 noktayı sırayla gösterin:

1. **1. Konuşmacı — Adım 0 (`1` tuşu):**
   - Üstteki şeritte `ARABA` ve `ARABB` girişlerinin yalnızca `42` baytında (2 bit) ayrıştığını, çıktıda ise 16 baytın tamamının değiştiğini gösterin.
   - Sağdaki `4×4 durum matrisi` içinde `s[0,0]..s[3,0]` sütun dizilimini işaret edin.
2. **1. Konuşmacı — Anahtar Türetme (`3` tuşu):**
   - `W[4]: A0FAFE17` butonuna tıklayıp sağ paneldeki 6 adımlı `RotWord → SubWord → Rcon[1]` hesabını gösterin.
3. **2. Konuşmacı — Şifreleme (`2` tuşu, `Tur 1`):**
   - `1. SubBytes` kartında `s[0,0] = 02` hücresine tıklayın: alttaki denetçide `6A → 91 → 02` adımını ve sağdaki 16×16 S-Box'ta `6. satır, A sütunu` kesişimini gösterin.
   - Ardından `3. MixColumns` kartında `s[0,1]` (kırmızı fark hücresi) üzerine tıklayıp `0x1B` taşma indirgemesini gösterin.
   - Klavyeden **`→`** tuşuyla **`Tur 2`**'ye geçin: tüm 16 hücrenin kırmızıya döndüğünü (tam yayılma) canlı kanıtlayın.
4. **1. Konuşmacı — Deşifreleme (`4` tuşu):**
   - `→` ile **`Ters Adım 10 (Tur 0)`**'a gidip `AddRoundKey` sonucunda `41 52 41 42 41` (`ARABA`) baytlarının birebir geri geldiğini gösterin.

---

## 4. Hoca Sorarsa: Hızlı Soru–Cevap Özeti

1. **Neden S-Box sabit bir rastgele tablo değil de `GF(2⁸)` tersi + afin dönüşümle üretiliyor?**
   - Çarpımsal ters doğrusal/diferansiyel kriptanalize karşı maksimum direnç sağlar; afin dönüşüm + `0x63` ise cebirsel yapıyı bozarak sabit noktaları (`S(x) = x` veya `S(x) = ¬x`) engeller.
2. **`0x11B` ve `0x1B` nereden geliyor?**
   - AES sonlu cismi $GF(2^8)$ üzerinde çalışır ve 8. dereceden indirgenemez polinom olarak $x^8 + x^4 + x^3 + x + 1$ (`0x11B`) seçilmiştir. Bir baytı `0x02` ile çarptığımızda 9. bite taşma (`x⁸`) olursa `0x11B` çıkarılır (XOR alınır); en üst bit zaten 8 bitlik alanı terk ettiği için pratikte alt 8 bit olan `0x1B` ile XOR yeterlidir.
3. **10. turda neden `MixColumns` yok?**
   - `MixColumns` anahtara bağımlı olmayan doğrusal bir matris çarpımıdır. Son turda uygulansaydı anahtarı bilmeyen biri de `InvMixColumns` ile bu adımı geri alabilirdi; yani güvenlik artırmaz, yalnızca şifreleme ile deşifreleme arasındaki yapısal simetriyi bozardı.
4. **Neden toplama (`+`) yerine `XOR` kullanılıyor?**
   - `XOR` kendi kendinin tersidir (`(A ⊕ K) ⊕ K = A`), bitler arasında elde (carry) üretmediği için sabit zamanda çalışır ve zamanlama yan-kanal saldırılarına karşı daha öngörülebilirdir.
5. **Anahtar genişletmede neden `Rcon` sabiti var?**
   - Tüm turların anahtarlarının aynı kaydırma/yerine koyma döngüsüne girmesini engellemek ve turlar arasındaki simetriyi (slide attack gibi zafiyetleri) kırmak için her 4 kelimede bir farklı `Rcon[i/4]` sabiti eklenir.
6. **Gerçek hayatta metin 16 bayttan uzunsa ne olur?**
   - Bu laboratuvar AES-128'in çekirdek **tek blok (128-bit)** fonksiyonunu gösterir. Gerçek uygulamalarda birden fazla 16 baytlık blok güvenli çalışma kipleriyle (`CBC`, `CTR`, özellikle kimlik doğrulamalı `GCM`) birleştirilir; `ECB` modu aynı düz metin bloklarından aynı şifreli bloğu ürettiği için tercih edilmez.
7. **`PKCS#7` dolgusu ile `00` dolgusunun farkı nedir?**
   - `00` dolgusu metin sonunda zaten `0x00` baytı varsa belirsizlik yaratabilir (sunumda okunurluğu kolaylaştırmak için varsayılan seçilidir). `PKCS#7` ise eksik bayt sayısı kadar aynı değeri (örneğin 11 bayt eksikse 11 adet `0x0B`) yazar; tam 16 baytlık veride bile 16 adet `0x10` eklediği için geri açmada belirsizlik bırakmaz.
