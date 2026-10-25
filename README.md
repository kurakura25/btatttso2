# AN TOÀN VÀ BẢO MẬT THÔNG TIN

## Bài tập: AES, RSA, SHA-256 và chữ ký số

**Môi trường:** .NET 8, C# WinForms 
**Mã nguồn:**

- `Bai1_AES/` – ứng dụng mã hóa đối xứng AES

- `Bai2_RSA/` – ứng dụng mã hóa bất đối xứng RSA, SHA-256, chữ ký số


# BÀI 1. MÃ HÓA AES

## Tổng quan

AES là mã hóa đối xứng: mã hóa và giải mã dùng chung một khóa.

Ứng dụng dạng Form gồm 3 trang: **Khóa**, **Văn bản**, **Tệp tin**.

Chế độ mã hóa: AES-CBC, đệm PKCS7, mỗi lần mã hóa sinh IV ngẫu nhiên 16 byte và đặt ở đầu bản mã.

| Tệp | Nội dung |
|---|---|
| `AesCore.cs` | Sinh khóa, lưu/nhập khóa, mã hóa văn bản, mã hóa tệp theo luồng, so sánh byte |
| `Ui.cs` | Bộ dựng giao diện nền trắng chữ đen |
| `MainForm.cs` | Giao diện và xử lý sự kiện |
| `Program.cs` | Điểm khởi chạy |

---

## Ý 1. Sinh khóa AES

**Phân tích:** khóa AES là dãy byte ngẫu nhiên có độ dài 16, 24 hoặc 32 byte tương ứng 128, 192, 256 bit. Dùng bộ sinh số ngẫu nhiên an toàn của hệ điều hành `RandomNumberGenerator`, không dùng `Random` vì dự đoán được.

```csharp
public static byte[] NewKey(int bits) => RandomNumberGenerator.GetBytes(bits / 8);
```

Khóa hiển thị dạng Base64 và Hex, kèm dấu vân tay SHA-256 (16 ký tự đầu) để nhận diện khóa mà không lộ khóa.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/c183a26b-e2e3-4661-9282-10eba87f5b7b" />


<p align="center"><em>Sinh khóa</em></p>

---

## Ý 2. Lưu khóa ra tệp

**Phân tích:** khóa là dữ liệu nhị phân nên lưu dạng Base64 trong tệp văn bản `.key`, dễ mở xem và sao chép, không mất byte.

```csharp
public static void SaveKey(string path, byte[] key) =>
    File.WriteAllText(path, Convert.ToBase64String(key));
```
<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/9436d970-e81e-46f9-99db-d45dd9d08f5a" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/9ee7ce98-e118-4edc-b2cd-2508a2dc0c59" />

<p align="center"><em>Lưu khóa</em></p>

---

## Ý 3. Nhập khóa từ tệp

**Phân tích:** đọc tệp, giải mã Base64, kiểm tra độ dài phải là 16, 24 hoặc 32 byte. Sai định dạng hoặc sai độ dài thì báo lỗi, không nạp khóa.

```csharp
var key = Convert.FromBase64String(File.ReadAllText(path).Trim());
if (key.Length is not (16 or 24 or 32)) throw new InvalidDataException("Khóa AES không hợp lệ");
```

Sau khi nhập, dấu vân tay phải trùng với lúc sinh khóa, chứng tỏ khóa không bị biến đổi.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/e74c6fd4-c781-4ce8-be9d-5c659e12fd88" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/59bbd489-8579-4cba-a109-a3b84929f689" />

<p align="center"><em>Nhập khóa</em></p>

---

## Ý 4. Mã hóa đoạn văn bản, hiển thị kết quả

**Phân tích:** văn bản đổi sang byte UTF-8 (giữ đúng tiếng Việt có dấu), mã hóa bằng AES-CBC, ghép IV vào đầu rồi đổi sang Base64 để hiển thị.

Định dạng bản mã: `Base64( IV 16 byte || dữ liệu mã hóa )`.

```csharp
byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(plain), aes.IV);
```

Do IV ngẫu nhiên, cùng một văn bản mã hóa hai lần cho hai bản mã khác nhau, nhưng giải mã ra kết quả giống nhau.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/f30a8d41-8692-495c-ba0d-320b1479f67f" />


<p align="center"><em>Mã hóa văn bản</em></p>

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/89073866-be74-40d3-b985-4fcf4f23929c" />


<p align="center"><em>Giải mã văn bản</em></p>

---

## Ý 5. Mã hóa tệp, lưu ra tệp

**Phân tích:** tệp hàng GB không thể đọc hết vào RAM. Mã hóa theo luồng: đọc từng khối 4 MB, đẩy qua `CryptoStream`, ghi ra tệp đích. Bộ nhớ sử dụng cố định vài chục MB bất kể kích thước tệp.

Định dạng tệp `.enc`: `IV (16 byte) || dữ liệu mã hóa`. Giải mã đọc 16 byte đầu làm IV rồi giải mã phần còn lại.

```csharp
using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
Pump(fin, cs, fin.Length, progress);
cs.FlushFinalBlock();
```

Tiến trình chạy trên luồng nền (`Task.Run`) nên giao diện không bị treo, có thanh tiến độ.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/d323c1e0-2b12-40a0-8f88-53e7e3efd657" />


<p align="center"><em>Mã hóa tệp</em></p>

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/27fb322b-03d9-4bc8-9308-256647afd8d0" />


<p align="center"><em>Giải mã tệp</em></p>

---

## Yêu cầu thử nghiệm: tệp hàng GB, đo thời gian, so sánh byte

**Phương pháp:**

- Nút **Tạo tệp thử nghiệm** sinh tệp ngẫu nhiên theo dung lượng MB nhập vào.

- Nút **Chạy toàn bộ** thực hiện lần lượt: mã hóa, giải mã, so sánh byte.

- Thời gian đo bằng `Stopwatch`, chỉ tính phần xử lý.

- So sánh byte: đọc song song tệp nguồn và tệp giải mã từng khối 4 MB, dừng ở byte khác nhau đầu tiên.

```csharp
int k = ba.AsSpan(0, n).CommonPrefixLength(bb.AsSpan(0, n));
if (k < n) return new(false, fa.Length, fb.Length, pos + k);
```

<img width="1912" height="1078" alt="image" src="https://github.com/user-attachments/assets/3fa42510-8a5f-4cc2-8420-f12590c0ec67" />

<img width="1916" height="1078" alt="image" src="https://github.com/user-attachments/assets/47db4b63-0571-4bf2-90b2-1428ae7bcd3a" />

<p align="center"><em>Thử nghiệm tệp lớn</em></p>

**Số liệu đo:

| Dung lượng | Mã hóa (s) | Giải mã (s) | MB/s mã hóa | MB/s giải mã | So sánh byte (s) | Kết quả so sánh |
|---:|---:|---:|---:|---:|---:|---|
| 100 MB | 0,26 | 0,19 | 385 | 526 | 0,08 | Giống nhau |
| 500 MB | 1,24 | 1,75 | 403 | 286 | 0,34 | Giống nhau |
| 1 GB | 2,82 | 2,48 | 363 | 413 | 0,68 | Giống nhau |
| 2 GB | 7,54 | 4,73 | 272 | 433 | 3,59 | Giống nhau |

Tệp `.enc` lớn hơn tệp gốc đúng 32 byte (16 byte IV và 16 byte đệm PKCS7): 1 GB gốc là 1.073.741.824 byte, tệp mã hóa là 1.073.741.856 byte.

## Kết luận 

- Giải mã ra tệp **giống nguồn tuyệt đối từng byte** ở mọi kích thước, kể cả 2 GB: AES-CBC cùng khóa và IV cho kết quả đảo ngược chính xác.

- Tốc độ xử lý ổn định quanh **270 – 530 MB/s**, thời gian tăng gần tuyến tính theo dung lượng (gấp đôi dung lượng thì thời gian khoảng gấp đôi). Độ phức tạp O(n).

- Mã hóa và giải mã có tốc độ cùng bậc; chênh lệch giữa các lần đo chủ yếu do tốc độ ổ đĩa và bộ nhớ đệm hệ điều hành, không do thuật toán.

- Tốc độ cao nhờ AES dùng phép toán đơn giản trên byte và được CPU hỗ trợ bằng tập lệnh AES-NI. Đây là lý do AES dùng để mã hóa **dữ liệu lớn**, còn RSA (Bài 2) chỉ dùng cho dữ liệu nhỏ như khóa AES.

- Mã hóa theo luồng giúp RAM không đổi khi tăng dung lượng tệp.

> Số liệu trong bảng đo trên máy thử nghiệm. Khi nộp, chạy lại ứng dụng trên máy cá nhân và thay bằng số liệu thực tế.

---

# BÀI 2. MÃ HÓA RSA, SHA-256, CHỮ KÝ SỐ

## Tổng quan

RSA là mã hóa bất đối xứng: cặp khóa gồm khóa công khai (n, e) và khóa riêng tư (n, d). Mã hóa bằng khóa này thì giải mã bằng khóa còn lại.

Ứng dụng Form gồm 8 trang, mỗi trang ứng với một ý của đề.

| Tệp | Nội dung |
|---|---|
| `RsaCore.cs` | Sinh khóa, xuất/nhập PEM, mã hóa, giải mã, SHA-256, chữ ký, đo tốc độ |
| `Asn1.cs` | Bộ đọc DER, giải thích từng byte trong PEM |
| `Ui.cs` | Bộ dựng giao diện nền trắng chữ đen |
| `MainForm.cs` | Giao diện và xử lý sự kiện |
| `Program.cs` | Điểm khởi chạy |

---

## Ý 1. Sinh cặp khóa

**Phân tích:** `RSA.Create(bits)` chọn hai số nguyên tố lớn p, q, tính n = p·q, chọn e = 65537, tính d là nghịch đảo của e theo modulo (p-1)(q-1). Hỗ trợ 1024, 2048, 3072, 4096 bit; mặc định 2048 bit.

```csharp
public static RSA Generate(int bits) => RSA.Create(bits);
```

Sinh khóa chạy trên luồng nền vì khóa 4096 bit có thể mất vài giây.

<img width="1915" height="1078" alt="image" src="https://github.com/user-attachments/assets/a91de9bd-f17a-416d-8615-d80bdec9e4a1" />


<p align="center"><em>Sinh cặp khóa</em></p>

---

## Ý 2. Xuất cặp khóa ra tệp PEM

**Phân tích:** xuất hai tệp `public.pem` và `private.pem`. Có hai định dạng:

| Định dạng | Khóa công khai | Khóa riêng tư |
|---|---|---|
| PKCS#1 | `BEGIN RSA PUBLIC KEY` | `BEGIN RSA PRIVATE KEY` |
| PKCS#8 / SPKI | `BEGIN PUBLIC KEY` | `BEGIN PRIVATE KEY` |

```csharp
r.ExportSubjectPublicKeyInfoPem();   // public.pem  (SPKI)
r.ExportPkcs8PrivateKeyPem();        // private.pem (PKCS#8)
```

<img width="1911" height="1078" alt="image" src="https://github.com/user-attachments/assets/5486c2ff-2979-406a-8541-a5b70f5843c8" />

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/653a1fdf-dd54-442a-9089-b5ad0bb22496" />

<p align="center"><em>Xuất PEM</em></p>

---

## Ý 3. Xem PEM và ý nghĩa các byte

**Phân tích:** tệp PEM gồm dòng `-----BEGIN ...-----`, phần Base64 (64 ký tự mỗi dòng), dòng `-----END ...-----`. Giải mã Base64 ra dữ liệu **DER**, là chuỗi khối TLV:

| Thành phần | Ý nghĩa |
|---|---|
| Tag (1 byte) | Loại dữ liệu: `30` SEQUENCE, `02` INTEGER, `03` BIT STRING, `04` OCTET STRING, `05` NULL, `06` OID |
| Length (1 – 5 byte) | Độ dài phần giá trị. Nếu byte đầu < `80` thì đó là độ dài. `81 xx` nghĩa là độ dài nằm trong 1 byte sau, `82 xx xx` là 2 byte sau |
| Value | Nội dung, có thể chứa các khối con |

**Khóa công khai PKCS#1 (2048 bit), tổng 270 byte:**

| Byte | Ý nghĩa |
|---|---|
| `30 82 01 0A` | SEQUENCE dài 266 byte, bao toàn bộ khóa |
| `02 82 01 01` + `00 CA 92 ...` | INTEGER dài 257 byte: **n**. Byte `00` đầu để số không bị hiểu là số âm |
| `02 03` + `01 00 01` | INTEGER dài 3 byte: **e** = 65537 |

**Khóa công khai SPKI (BEGIN PUBLIC KEY), tổng 294 byte:**

| Byte | Ý nghĩa |
|---|---|
| `30 82 01 22` | SEQUENCE ngoài cùng, dài 290 byte |
| `30 0D` | SEQUENCE nhận dạng thuật toán, dài 13 byte |
| `06 09 2A 86 48 86 F7 0D 01 01 01` | OID `1.2.840.113549.1.1.1` = rsaEncryption |
| `05 00` | NULL, tham số rỗng |
| `03 82 01 0F 00` | BIT STRING dài 271 byte; byte `00` là số bit đệm |
| `30 82 01 0A ...` | bên trong là khóa PKCS#1 công khai (n, e) như bảng trên |

**Khóa riêng tư PKCS#1:** SEQUENCE gồm 9 INTEGER theo thứ tự:

| Thứ tự | Trường | Ý nghĩa |
|---:|---|---|
| 1 | version | luôn bằng 0 |
| 2 | n | modulus |
| 3 | e | số mũ công khai |
| 4 | d | số mũ riêng, khóa bí mật |
| 5 | p | thừa số nguyên tố thứ nhất |
| 6 | q | thừa số nguyên tố thứ hai |
| 7 | dP | d mod (p-1) |
| 8 | dQ | d mod (q-1) |
| 9 | qInv | q⁻¹ mod p, dùng tăng tốc giải mã theo định lý số dư Trung Hoa |

**Khóa riêng tư PKCS#8:** `30 82 ...` bao ngoài gồm version `02 01 00`, nhận dạng thuật toán (OID rsaEncryption), rồi OCTET STRING `04 82 ...` chứa nguyên khối khóa riêng PKCS#1 ở trên.

Trang này mở tệp PEM bất kỳ và hiển thị song song: byte DER dạng hex (trái) và ý nghĩa từng khối (phải), có thụt lề thể hiện quan hệ cha con.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/78f5fff2-277f-48ce-93ec-46403d321b7c" />


<p align="center"><em>Cấu trúc PEM công khai</em></p>

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/f3461583-0306-4399-aa0a-79acec7767fa" />

<p align="center"><em>Cấu trúc PEM riêng tư</em></p>

---

## Ý 4. Nhập PEM, lấy n, e (công khai) và n, e, d, ... (riêng tư)

**Phân tích:** `ImportFromPem` nhận cả bốn kiểu nhãn PEM. Sau khi nhập, `ExportParameters` trả về các thành phần số học:

- Khóa công khai: **n**, **e**.

- Khóa riêng tư: **n**, **e**, **d**, **p**, **q**, **dP**, **dQ**, **qInv**.

```csharp
var r = RSA.Create();
r.ImportFromPem(pem);
var p = r.ExportParameters(isPrivate);   // p.Modulus, p.Exponent, p.D, p.P, p.Q ...
```

Nhập sai loại (chọn tệp công khai ở nút riêng tư) thì báo lỗi. Khóa sau khi nhập được dùng cho các trang mã hóa, giải mã, chữ ký.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/39abc1b2-289b-4d80-9a2f-55d4c0b3247b" />


<p align="center"><em>Nhập khóa công khai</em></p>

<img width="1916" height="1078" alt="image" src="https://github.com/user-attachments/assets/bace66f1-fd7e-4ce0-9226-76346879b1d2" />

<p align="center"><em>Nhập khóa riêng tư</em></p>

---

## Ý 5. Mã hóa dữ liệu bằng khóa vừa nhập

**Phân tích:** dùng đệm **OAEP-SHA256**. Số byte tối đa mã hóa được:

`k − 2·hLen − 2 = 256 − 2·32 − 2 = 190 byte` (khóa 2048 bit, k = 256 byte).

Đây là lý do đề giới hạn 190 byte. Khóa AES-256 dài 32 byte, Base64 gồm 44 ký tự, nằm trong giới hạn.

```csharp
return pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
```

- Dữ liệu nhập là văn bản hoặc Base64 (tích chọn), nút **Sinh khóa AES-256** tạo ngay 32 byte ngẫu nhiên.

- Bộ đếm hiển thị `n / 190 byte`; vượt giới hạn thì báo lỗi.

- Bản mã luôn dài 256 byte, lưu dạng Base64 ra tệp.

- OAEP có thành phần ngẫu nhiên nên mã hóa cùng dữ liệu hai lần cho hai bản mã khác nhau.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/307fbbcd-6576-4781-aaf7-49bf7720e840" />


<p align="center"><em>Mã hóa RSA</em></p>

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/0e63f89f-54e1-4d3c-853b-82d73e619f15" />


<p align="center"><em>Lưu bản mã</em></p>

---

## Ý 6. Giải mã và so sánh với dữ liệu gốc

**Phân tích:** đầu vào là PEM riêng tư và tệp Base64 của bản mã. Giải mã bằng OAEP-SHA256 rồi so sánh mảng byte với dữ liệu gốc (Base64).

```csharp
bool same = plain.AsSpan().SequenceEqual(orig);
```

Kết quả hiển thị rõ **GIỐNG NHAU** hoặc **KHÁC NHAU** kèm số byte. Dùng sai khóa riêng tư thì giải mã ném lỗi, không trả ra dữ liệu.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/0d7a4737-65e0-42e2-9c7d-efcc246f3c3b" />

<p align="center"><em>Giải mã và so sánh</em></p>

---

## Ý 7. Đánh giá tốc độ: khóa công khai (e nhỏ) so với khóa riêng tư (d lớn)

**Phân tích:** RSA tính `c = m^e mod n` (mã hóa) và `m = c^d mod n` (giải mã). e = 65537 chỉ có 17 bit, d có độ dài xấp xỉ n (2047 bit với khóa 2048). Số phép nhân modular tỉ lệ với số bit của số mũ nên phép dùng d chậm hơn nhiều.

Ứng dụng đo 4 phép, mỗi phép chạy lặp trong khoảng thời gian cố định (mặc định 700 ms) rồi tính trung bình:

| Phép đo | Số mũ |
|---|---|
| Mã hóa OAEP bằng khóa công khai | e |
| Giải mã OAEP bằng khóa riêng tư | d |
| Lũy thừa modular thô `m^e mod n` (`BigInteger.ModPow`) | e |
| Lũy thừa modular thô `m^d mod n` | d |

```csharp
var (c, ms) = Measure(() => BigInteger.ModPow(m, d, n), durationMs);
```
<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/0c1dc097-a30c-463d-9818-4f74ca7af807" />


<p align="center"><em>Đánh giá tốc độ</em></p>

**Số liệu đo (.NET 8, CPU 1 nhân):**

| Khóa | Mã hóa (e) ms/lần | Giải mã (d) ms/lần | Giải mã / Mã hóa | `m^e` ms/lần | `m^d` ms/lần | `m^d` / `m^e` |
|---:|---:|---:|---:|---:|---:|---:|
| 1024 bit | 0,019 | 0,126 | 6,6 lần | 0,186 | 19,990 | 107 lần |
| 2048 bit | 0,066 | 1,346 | 20,4 lần | 0,457 | 55,251 | 121 lần |
| 3072 bit | 0,065 | 2,125 | 32,7 lần | 0,428 | 100,958 | 236 lần |
| 4096 bit | 0,086 | 4,602 | 53,5 lần | 0,663 | 226,712 | 342 lần |

**Kết luận:**

- Khóa công khai (e nhỏ) nhanh hơn khóa riêng tư (d lớn) ở mọi độ dài khóa.

- Với phép lũy thừa thô, chênh lệch từ **107 đến 342 lần**, tăng theo độ dài khóa vì số bit của d tăng còn e cố định.

- Với hàm thư viện, chênh lệch nhỏ hơn (6 – 54 lần) vì giải mã dùng p, q, dP, dQ, qInv (định lý số dư Trung Hoa) để tách thành hai phép lũy thừa nửa kích thước, nhanh hơn khoảng 3 – 4 lần so với dùng thẳng d.

- Tăng gấp đôi độ dài khóa (2048 lên 4096) làm giải mã chậm khoảng 3,4 lần, trong khi mã hóa gần như không đổi.

- RSA chậm hơn AES hàng trăm đến hàng nghìn lần, nên chỉ dùng để trao đổi khóa AES, còn dữ liệu lớn mã hóa bằng AES.

> Số liệu trong bảng đo trên máy thử nghiệm. Khi nộp, chạy lại và thay bằng số liệu máy cá nhân; xu hướng chênh lệch giữ nguyên.

---

## Ý 8. Giao diện sinh chuỗi băm SHA-256

**Phân tích:** SHA-256 nhận dữ liệu độ dài bất kỳ, trả về 256 bit (32 byte, 64 ký tự hex). Giao diện tính hash ngay khi gõ, giữ hash ngay trước đó và so sánh:

- Số bit khác nhau trên 256 bit và tỉ lệ phần trăm.

- Số ký tự hex khác nhau trên 64 ký tự; ký tự khác hiển thị nền đen chữ trắng.

```csharp
public static int BitDiff(byte[] a, byte[] b) { ... BitOperations.PopCount((uint)(a[i] ^ b[i])) ... }
```

Nút **Đổi 1 ký tự cuối** tạo thay đổi nhỏ nhất. Nút **Thử 1000 lần đổi 1 bit** kiểm chứng thống kê.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/3cbb4118-baaf-49fe-a148-f87433393d1c" />


<p align="center"><em>Băm SHA-256</em></p>

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/087d9930-79a9-4e97-8df9-d63a5ad9f42b" />


<p align="center"><em>Hiệu ứng thác đổ</em></p>

**Kết quả thống kê (1000 thông điệp 64 byte, mỗi lần đổi đúng 1 bit):**

| Chỉ số | Giá trị |
|---|---|
| Số bit hash thay đổi trung bình | 128,32 / 256 (50,1%) |
| Ít nhất | 104 bit |
| Nhiều nhất | 154 bit |

**Đánh giá:** chỉ thay đổi 1 bit đầu vào làm khoảng một nửa số bit hash đổi, không theo quy luật. Đây là **hiệu ứng thác đổ** (avalanche effect). Hệ quả: không suy ra được dữ liệu từ hash, không tìm được hai dữ liệu khác nhau có cùng hash, và hash phát hiện được mọi sửa đổi dù rất nhỏ.

---

## Ý 9. Chữ ký số và đề xuất để mỗi lần ký ra chữ ký khác nhau

### Phân tích

Chữ ký số = RSA khóa riêng tư áp lên hash của dữ liệu:

`S = (đệm(SHA-256(M)))^d mod n`

Xác thực: dùng khóa công khai tính `S^e mod n` rồi so với hash của dữ liệu nhận được.

Dữ liệu khác nhau thì hash khác nhau nên chữ ký khác nhau. Mong muốn của đề: **cùng dữ liệu, cùng khóa riêng tư nhưng mỗi lần ký ra một chữ ký khác nhau**.

Với đệm PKCS#1 v1.5 truyền thống, mọi thành phần đều xác định (tiền tố cố định, DigestInfo, hash), không có yếu tố ngẫu nhiên, nên chữ ký lặp lại hoàn toàn. Muốn khác nhau phải đưa **yếu tố ngẫu nhiên** vào trước phép ký, mà người xác thực vẫn khôi phục hoặc nhận được yếu tố đó.

### Phương pháp đề xuất

| Phương pháp | Cách làm | Người xác thực lấy yếu tố ngẫu nhiên ở đâu |
|---|---|---|
| **A. RSA-PSS** (khuyến nghị) | Sinh salt ngẫu nhiên 32 byte, tính `H' = SHA-256(00×8 ‖ SHA-256(M) ‖ salt)`, mặt nạ hóa salt vào khối mã hóa EM rồi ký EM | Salt nằm ngay trong chữ ký, xác thực tự khôi phục. Không cần gửi thêm gì |
| **B. Nonce** | Sinh nonce 16 byte, ký `SHA-256(M ‖ nonce)`, gửi gói `nonce ‖ chữ ký` | Nonce gửi kèm gói |
| **C. Nonce + mốc thời gian** | Như B, thêm thời gian ký vào dữ liệu được ký | Nonce và thời gian gửi kèm. Có thêm khả năng chống phát lại |

Phương pháp A là chuẩn (RFC 8017), có chứng minh an toàn, thư viện hỗ trợ sẵn. Phương pháp B, C đơn giản, tự cài đặt được trên bất kỳ thư viện RSA nào.

```csharp
// A. PSS
priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

// B. Nonce
byte[] nonce = RandomNumberGenerator.GetBytes(16);
byte[] sig = priv.SignData(data.Concat(nonce).ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
return nonce.Concat(sig).ToArray();
```

Giao diện cho chọn một trong ba phương pháp (kèm PKCS#1 v1.5 làm đối chứng), ký 5 lần liên tiếp cùng dữ liệu, thống kê số chữ ký khác nhau, xác thực lại và thử xác thực khi dữ liệu bị sửa 1 bit.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/43386d7c-c522-4db9-b27e-188472cd1f90" />


<p align="center"><em>Ký PKCS#1 v1.5</em></p>

<img width="1911" height="1078" alt="image" src="https://github.com/user-attachments/assets/706d823c-98d2-4fe4-b0cf-a266d35e1336" />


<p align="center"><em>Ký RSA-PSS</em></p>

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/8ed8fdde-c75e-447e-a603-19f4f9494eca" />


<p align="center"><em>Ký có nonce</em></p>

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/a5b2a965-8be7-477f-a9cb-364243deb48d" />


<p align="center"><em>Xác thực chữ ký</em></p>

### Kết quả (cùng dữ liệu, cùng khóa riêng, ký 5 lần)

| Phương pháp | Số chữ ký khác nhau | Xác thực bằng khóa công khai | Xác thực khi dữ liệu bị sửa |
|---|---:|---|---|
| PKCS#1 v1.5 (đối chứng) | 1 / 5 | Hợp lệ | Không hợp lệ |
| RSA-PSS | 5 / 5 | Hợp lệ | Không hợp lệ |
| PKCS#1 v1.5 + nonce | 5 / 5 | Hợp lệ | Không hợp lệ |

### Kết luận

- PKCS#1 v1.5 có tính xác định nên chữ ký lặp lại. Đạt mong muốn của đề cần thêm yếu tố ngẫu nhiên.

- RSA-PSS và phương pháp nonce đều cho chữ ký khác nhau ở mọi lần ký, vẫn xác thực được bằng cùng một khóa công khai.

- Chữ ký khác nhau **không làm giảm tính toàn vẹn**: sửa dù 1 bit dữ liệu thì xác thực thất bại ở cả ba phương pháp.

- Khuyến nghị dùng **RSA-PSS** trong thực tế vì là chuẩn, không cần truyền thêm trường nào.

---
