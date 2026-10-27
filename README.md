# AES-128 İnteraktif Kriptoloji ve Tahta Çözüm Aracı

Bu proje, Kriptoloji dersi kapsamında **FIPS-197 (Advanced Encryption Standard - Rijndael)** standardını bit ve bayt düzeyinde simüle etmek, tahta çözümlerini doğrulamak ve çığ etkisini (avalanche effect) görselleştirmek amacıyla geliştirilmiştir.

Harici bir şifreleme kütüphanesi kullanılmamıştır; $GF(2^8)$ sonlu cisim aritmetiği, S-Box üretim matrisi, anahtar genişletme (Key Schedule) ve ters dönüşüm adımlarının tamamı saf JavaScript ile sıfırdan gerçeklenmiştir.

## Temel Özellikler

* **Adım 0 (Blok Hazırlama ve Durum Matrisi):** Düz metnin ASCII ve Hex karşılıklarını çıkarır, 16 bayta tamamlar ve AES standardına uygun olarak $4 \times 4$ durum (state) tablosuna sütun-öncelikli (column-major) dizilimle yerleştirir.
* **Canlı Çığ Etkisi (Avalanche Effect) Karşılaştırması:** Ana metin (`ARABA`) ile karşılaştırma metnini (`ARABB`) aynı anda şifreler. Girdideki 2 bitlik farkın turlar ilerledikçe `ShiftRows` ve `MixColumns` adımlarıyla tüm matrise nasıl yayıldığını ve 10. tur sonunda 128 bitin 65 bitini (%50.8) nasıl değiştirdiğini canlı olarak işaretler.
* **Tahta Çözüm Denetçisi (Hücre Matematiği):** Matris üzerindeki herhangi bir bayta tıklandığında o hücrenin nasıl hesaplandığını adım adım gösterir:
  * **SubBytes / InvSubBytes:** $GF(2^8)$ üzerinde $m(x) = x^8 + x^4 + x^3 + x + 1$ ($\text{0x11B}$) indirgenemez polinomuna göre çarpımsal tersini, afin dönüşümünü ve $16 \times 16$ S-Box tablosundaki satır/sütun kesişimini verir.
  * **ShiftRows / InvShiftRows:** İlgili satırın kaç birim sola veya sağa kaydığını ve baytın eski/yeni koordinatlarını gösterir.
  * **MixColumns / InvMixColumns:** Seçili sütunun sabit MDS matrisiyle çarpımını, $\text{0x02}$ (`xtime`) adımında 8 bitten taşma (MSB=1) varsa $\text{0x1B}$ ile XOR indirgemesini ve 4 terimin 8-bit ikilik (binary) alt alta toplamını tablo halinde sunar.
  * **AddRoundKey:** Durum baytı ile tur anahtarı baytının bit düzeyinde XOR işlemini gösterir.
* **Anahtar Türetme (Key Expansion):** 128-bit başlangıç anahtarından 11 tur için üretilen 44 kelimenin (`W[0]..W[43]`) tamamını listeler. 4'ün katı olan sütunlarda uygulanan `RotWord`, `SubWord` ve `Rcon` adımlarını açıklar.
* **Geri Açma (Deşifreleme):** 10. tur sonunda elde edilen şifreli metnin (`EA 38 5F A9...`) ters adımlarla (`InvShiftRows`, `InvSubBytes`, `AddRoundKey`, `InvMixColumns`) başlangıçtaki düz metne dönüşünü gösterir.

## Doğrulama ve Test Vektörü

Uygulama varsayılan olarak ders sunumundaki parametrelerle açılır:

* **Düz Metin:** `ARABA` (`41 52 41 42 41 00 00 00 00 00 00 00 00 00 00 00`)
* **Gizli Anahtar (FIPS-197):** `2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C`
* **Başlangıç AddRoundKey Çıktısı:** `6A 2C 54 54 69 AE D2 A6 AB F7 15 88 09 CF 4F 3C`
* **1. Tur Sonu:** `21 2B 8C 61 7D CA CE 0D 66 8A FD 7D CA 8F 20 51`
* **10. Tur Sonu (Şifreli Metin):** `EA 38 5F A9 15 11 6B 6D 7C 3A EB A0 1F A0 0C C4`

## Dosya Yapısı

```text
├── index.html   # Semantik arayüz iskeleti
├── style.css    # Koyu/Açık tema destekli tablo ve matris stilleri
├── app.js       # GF(2^8) aritmetiği, AES-128 motoru ve hücre denetçisi
└── README.md    # Proje dokümantasyonu