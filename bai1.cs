using System.Diagnostics;
using System.Drawing;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;

namespace Bai2_RSA;

// ===== Program.cs =====
static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

// ===== RsaCore.cs =====
public enum SignMode { Pkcs1, Pss, Pkcs1Nonce }

public sealed record BenchRow(int Bits, string Op, string Exponent, int Count, double TotalMs)
{
    public double AvgMs => TotalMs / Count;
    public double PerSec => Count * 1000.0 / TotalMs;
}

/// <summary>Toàn bộ nghiệp vụ RSA, băm và chữ ký số (không phụ thuộc giao diện).</summary>
public static class RsaCore
{
    // ---------- 1, 2. Sinh khóa, xuất PEM ----------
    public static RSA Generate(int bits) => RSA.Create(bits);

    public static string PublicPem(RSA r, bool pkcs1) =>
        pkcs1 ? r.ExportRSAPublicKeyPem() : r.ExportSubjectPublicKeyInfoPem();

    public static string PrivatePem(RSA r, bool pkcs1) =>
        pkcs1 ? r.ExportRSAPrivateKeyPem() : r.ExportPkcs8PrivateKeyPem();

    public static RSA PublicOnly(RSA full)
    {
        var r = RSA.Create();
        r.ImportParameters(full.ExportParameters(false));
        return r;
    }

    // ---------- 4. Nhập PEM ----------
    public static RSA ImportPem(string pem, out bool isPrivate)
    {
        var r = RSA.Create();
        r.ImportFromPem(pem);
        isPrivate = pem.Contains("PRIVATE KEY");
        return r;
    }

    public static string Hex(byte[]? b) => b == null ? "(không có)" : Convert.ToHexString(b);

    public static string Describe(RSA r, bool isPrivate)
    {
        var p = r.ExportParameters(isPrivate);
        var sb = new StringBuilder();
        sb.AppendLine($"Loại khóa : {(isPrivate ? "Khóa riêng tư (private key)" : "Khóa công khai (public key)")}");
        sb.AppendLine($"Độ dài    : {r.KeySize} bit");
        sb.AppendLine();
        sb.AppendLine($"n (Modulus) - {p.Modulus!.Length} byte:");
        sb.AppendLine(Hex(p.Modulus));
        sb.AppendLine();
        sb.AppendLine($"e (Exponent) = {new BigInteger(p.Exponent!, true, true)}  (hex {Hex(p.Exponent)})");
        if (isPrivate)
        {
            sb.AppendLine();
            sb.AppendLine($"d (số mũ riêng) - {p.D!.Length} byte:");
            sb.AppendLine(Hex(p.D));
            sb.AppendLine();
            sb.AppendLine($"p - {p.P!.Length} byte:");
            sb.AppendLine(Hex(p.P));
            sb.AppendLine();
            sb.AppendLine($"q - {p.Q!.Length} byte:");
            sb.AppendLine(Hex(p.Q));
            sb.AppendLine();
            sb.AppendLine("dP = d mod (p-1):"); sb.AppendLine(Hex(p.DP));
            sb.AppendLine();
            sb.AppendLine("dQ = d mod (q-1):"); sb.AppendLine(Hex(p.DQ));
            sb.AppendLine();
            sb.AppendLine("qInv = q^-1 mod p:"); sb.AppendLine(Hex(p.InverseQ));
        }
        return sb.ToString();
    }

    // ---------- 5, 6. Mã hóa / giải mã ----------
    // OAEP-SHA256: số byte tối đa = k - 2*hLen - 2 = 256 - 64 - 2 = 190 (khóa 2048 bit)
    public static int MaxBytes(RSA r) => r.KeySize / 8 - 2 * 32 - 2;

    public static byte[] Encrypt(RSA pub, byte[] data)
    {
        if (data.Length > MaxBytes(pub))
            throw new ArgumentException($"Dữ liệu {data.Length} byte vượt giới hạn {MaxBytes(pub)} byte của khóa {pub.KeySize} bit");
        return pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] Decrypt(RSA priv, byte[] cipher) =>
        priv.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);

    // ---------- 8. SHA-256 ----------
    public static byte[] Sha256(string s) => SHA256.HashData(Encoding.UTF8.GetBytes(s));

    public static int BitDiff(byte[] a, byte[] b)
    {
        int n = 0;
        for (int i = 0; i < a.Length; i++) n += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return n;
    }

    /// <summary>Đổi đúng 1 bit ngẫu nhiên của thông điệp, đếm số bit băm thay đổi.</summary>
    public static (double mean, int min, int max) Avalanche(int trials)
    {
        var rnd = new Random(7);
        int sum = 0, min = 256, max = 0;
        for (int t = 0; t < trials; t++)
        {
            byte[] m = new byte[64];
            rnd.NextBytes(m);
            byte[] h1 = SHA256.HashData(m);
            int bit = rnd.Next(m.Length * 8);
            m[bit / 8] ^= (byte)(1 << (bit % 8));
            int d = BitDiff(h1, SHA256.HashData(m));
            sum += d; min = Math.Min(min, d); max = Math.Max(max, d);
        }
        return ((double)sum / trials, min, max);
    }

    // ---------- 9. Chữ ký số ----------
    // Pkcs1      : xác định  -> cùng dữ liệu + cùng khóa luôn ra cùng chữ ký
    // Pss        : salt ngẫu nhiên 32 byte trước khi ký -> mỗi lần một chữ ký khác nhau
    // Pkcs1Nonce : ký (dữ liệu || nonce 16 byte ngẫu nhiên), gửi kèm nonce -> mỗi lần khác nhau
    public static byte[] Sign(RSA priv, byte[] data, SignMode mode)
    {
        switch (mode)
        {
            case SignMode.Pkcs1:
                return priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            case SignMode.Pss:
                return priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            default:
                byte[] nonce = RandomNumberGenerator.GetBytes(16);
                byte[] sig = priv.SignData(data.Concat(nonce).ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return nonce.Concat(sig).ToArray();
        }
    }

    public static bool Verify(RSA pub, byte[] data, byte[] pkg, SignMode mode)
    {
        switch (mode)
        {
            case SignMode.Pkcs1:
                return pub.VerifyData(data, pkg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            case SignMode.Pss:
                return pub.VerifyData(data, pkg, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            default:
                if (pkg.Length <= 16) return false;
                byte[] nonce = pkg[..16], sig = pkg[16..];
                return pub.VerifyData(data.Concat(nonce).ToArray(), sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    // ---------- 7. Đo tốc độ ----------
    static (int count, double ms) Measure(Action op, int durationMs)
    {
        op(); // khởi động
        var sw = Stopwatch.StartNew();
        int n = 0;
        do { op(); n++; } while (sw.ElapsedMilliseconds < durationMs);
        sw.Stop();
        return (n, sw.Elapsed.TotalMilliseconds);
    }

    public static List<BenchRow> Benchmark(int bits, int durationMs)
    {
        using var full = RSA.Create(bits);
        using var pub = PublicOnly(full);
        var par = full.ExportParameters(true);
        var n = new BigInteger(par.Modulus!, true, true);
        var e = new BigInteger(par.Exponent!, true, true);
        var d = new BigInteger(par.D!, true, true);
        var m = new BigInteger(RandomNumberGenerator.GetBytes(par.Modulus!.Length - 2), true, true);

        byte[] data = RandomNumberGenerator.GetBytes(32);
        byte[] cipher = pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

        var rows = new List<BenchRow>();
        string eTxt = $"e = {e} (nhỏ)";
        string dTxt = $"d ({d.GetBitLength()} bit)";

        var (c1, t1) = Measure(() => pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256), durationMs);
        rows.Add(new(bits, "Mã hóa OAEP bằng khóa công khai", eTxt, c1, t1));
        var (c2, t2) = Measure(() => full.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256), durationMs);
        rows.Add(new(bits, "Giải mã OAEP bằng khóa riêng tư", dTxt, c2, t2));
        var (c3, t3) = Measure(() => BigInteger.ModPow(m, e, n), durationMs);
        rows.Add(new(bits, "Lũy thừa modular thô m^e mod n", eTxt, c3, t3));
        var (c4, t4) = Measure(() => BigInteger.ModPow(m, d, n), durationMs);
        rows.Add(new(bits, "Lũy thừa modular thô m^d mod n", dTxt, c4, t4));
        return rows;
    }
}

// ===== Asn1.cs =====
public sealed class Asn1Node
{
    public int Offset, Tag, HeaderLen, Length;
    public List<Asn1Node> Kids = new();
    public string Role = "";
}

/// <summary>Bộ đọc DER tối giản để giải thích từng byte trong tệp PEM.</summary>
public static class Asn1
{
    static readonly string[] Pkcs1Private =
    {
        "version = 0", "n – modulus (n = p·q)", "e – số mũ công khai", "d – số mũ riêng (khóa bí mật)",
        "p – số nguyên tố thứ nhất", "q – số nguyên tố thứ hai", "dP = d mod (p-1)", "dQ = d mod (q-1)", "qInv = q^-1 mod p"
    };
    static readonly string[] Pkcs1Public = { "n – modulus (n = p·q)", "e – số mũ công khai" };

    public static (string label, byte[] der) PemToDer(string pem)
    {
        var m = Regex.Match(pem, @"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", RegexOptions.Singleline);
        if (!m.Success) throw new InvalidDataException("Không tìm thấy khung -----BEGIN ...----- / -----END ...-----");
        string b64 = Regex.Replace(m.Groups[2].Value, @"\s+", "");
        return (m.Groups[1].Value, Convert.FromBase64String(b64));
    }

    public static Asn1Node Parse(byte[] d)
    {
        int pos = 0;
        var root = Read(d, ref pos, d.Length);
        AssignRoles(d, root);
        return root;
    }

    static Asn1Node Read(byte[] d, ref int pos, int end)
    {
        var n = new Asn1Node { Offset = pos };
        if (pos + 2 > end) throw new InvalidDataException("DER bị cắt cụt");
        n.Tag = d[pos++];
        int len = d[pos++];
        if ((len & 0x80) != 0)
        {
            int c = len & 0x7F;
            if (c == 0 || c > 4 || pos + c > end) throw new InvalidDataException("Độ dài DER không hợp lệ");
            len = 0;
            for (int i = 0; i < c; i++) len = (len << 8) | d[pos++];
        }
        n.HeaderLen = pos - n.Offset;
        n.Length = len;
        int vs = pos, ve = pos + len;
        if (ve > end) throw new InvalidDataException("Độ dài DER vượt quá dữ liệu");

        if ((n.Tag & 0x20) != 0)
        {
            while (pos < ve) n.Kids.Add(Read(d, ref pos, ve));
        }
        else if (n.Tag == 0x03 && len > 2 && d[vs] == 0x00 && d[vs + 1] == 0x30)      // BIT STRING chứa SEQUENCE
        {
            TryNested(d, n, vs + 1, ve);
        }
        else if (n.Tag == 0x04 && len > 1 && d[vs] == 0x30)                              // OCTET STRING chứa SEQUENCE
        {
            TryNested(d, n, vs, ve);
        }
        pos = ve;
        return n;
    }

    static void TryNested(byte[] d, Asn1Node n, int start, int end)
    {
        try { int p = start; n.Kids.Add(Read(d, ref p, end)); }
        catch (Exception) { n.Kids.Clear(); }
    }

    static void AssignRoles(byte[] d, Asn1Node n)
    {
        if (n.Tag == 0x30 && n.Kids.Count > 0 && n.Kids.All(k => k.Tag == 0x02))
        {
            string[]? roles = n.Kids.Count == 9 ? Pkcs1Private : n.Kids.Count == 2 ? Pkcs1Public : null;
            if (roles != null) for (int i = 0; i < roles.Length; i++) n.Kids[i].Role = roles[i];
        }
        if (n.Tag == 0x30 && n.Kids.Count >= 3 && n.Kids[0].Tag == 0x02 && n.Kids[1].Tag == 0x30)
            n.Kids[0].Role = "version = 0 (PKCS#8)";
        foreach (var k in n.Kids) AssignRoles(d, k);
    }

    // ---------- Xuất văn bản giải thích ----------
    public static string Dump(byte[] d, Asn1Node root)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Offset  Byte tiêu đề(tag, độ dài)   Cấu trúc / Ý nghĩa");
        sb.AppendLine(new string('-', 78));
        Walk(d, root, 0, sb);
        return sb.ToString();
    }

    static void Walk(byte[] d, Asn1Node n, int depth, StringBuilder sb)
    {
        string hdr = string.Join(" ", Enumerable.Range(n.Offset, n.HeaderLen).Select(i => d[i].ToString("X2")));
        string indent = new(' ', depth * 2);
        sb.AppendLine($"{n.Offset:D4}    {hdr,-16}  {indent}{TagName(n.Tag)}, dài {n.Length} byte");
        string meaning = Meaning(d, n);
        if (meaning.Length > 0) sb.AppendLine($"{"",-26}{indent}=> {meaning}");
        foreach (var k in n.Kids) Walk(d, k, depth + 1, sb);
    }

    static string TagName(int t) => t switch
    {
        0x30 => "SEQUENCE (30)", 0x02 => "INTEGER (02)", 0x03 => "BIT STRING (03)", 0x04 => "OCTET STRING (04)",
        0x05 => "NULL (05)", 0x06 => "OBJECT IDENTIFIER (06)", _ => $"TAG {t:X2}"
    };

    static string Meaning(byte[] d, Asn1Node n)
    {
        int vs = n.Offset + n.HeaderLen;
        switch (n.Tag)
        {
            case 0x30: return n.Role.Length > 0 ? n.Role : "Nhóm các trường nối tiếp nhau";
            case 0x02:
            {
                string hex = Short(d, vs, n.Length);
                string s = n.Role.Length > 0 ? n.Role + ": " : "Số nguyên: ";
                s += hex;
                if (n.Length <= 4) s += " = " + new BigInteger(d.AsSpan(vs, n.Length), true, true);
                if (n.Length > 1 && d[vs] == 0x00) s += "  [byte 00 đầu chỉ để số không bị hiểu là số âm]";
                return s;
            }
            case 0x06: { string oid = Oid(d, vs, n.Length); return oid + (oid == "1.2.840.113549.1.1.1" ? " = rsaEncryption (thuật toán RSA)" : ""); }
            case 0x05: return "Tham số rỗng";
            case 0x03: return n.Kids.Count > 0 ? "Byte 00 đầu = số bit đệm; phần còn lại chứa khóa công khai PKCS#1" : "Chuỗi bit";
            case 0x04: return n.Kids.Count > 0 ? "Chứa khóa riêng PKCS#1 (RSAPrivateKey) bên trong" : "Chuỗi byte";
            default: return "";
        }
    }

    static string Short(byte[] d, int start, int len)
    {
        string H(int a, int c) => string.Join(" ", Enumerable.Range(a, c).Select(i => d[i].ToString("X2")));
        return len <= 10 ? H(start, len) : $"{H(start, 6)} ... {H(start + len - 2, 2)} ({len} byte)";
    }

    static string Oid(byte[] d, int start, int len)
    {
        var parts = new List<string>();
        parts.Add((d[start] / 40).ToString());
        parts.Add((d[start] % 40).ToString());
        long v = 0;
        for (int i = 1; i < len; i++)
        {
            v = (v << 7) | (uint)(d[start + i] & 0x7F);
            if ((d[start + i] & 0x80) == 0) { parts.Add(v.ToString()); v = 0; }
        }
        return string.Join(".", parts);
    }

    public static string HexDump(byte[] d)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < d.Length; i += 16)
        {
            int c = Math.Min(16, d.Length - i);
            sb.Append($"{i:D4}  ");
            for (int j = 0; j < c; j++) sb.Append(d[i + j].ToString("X2")).Append(' ');
            sb.AppendLine();
        }
        return sb.ToString();
    }
}

// ===== Ui.cs =====
/// <summary>Bộ dựng giao diện dùng chung: nền trắng, chữ đen, viền đen mảnh.</summary>
static class Ui
{
    public static readonly Font F = new("Segoe UI", 10f);
    public static readonly Font FB = new("Segoe UI Semibold", 10f);
    public static readonly Font FT = new("Segoe UI Semibold", 20f);
    public static readonly Font FM = new("Consolas", 10f);
    static readonly Color Hover = Color.FromArgb(235, 235, 235);
    static readonly Color Active = Color.FromArgb(240, 240, 240);

    public static Button Btn(string text, EventHandler onClick, int width = 190)
    {
        var b = new Button
        {
            Text = text, Width = width, Height = 38, Font = F,
            FlatStyle = FlatStyle.Flat, BackColor = Color.White, ForeColor = Color.Black,
            Margin = new Padding(0, 6, 10, 6), Cursor = Cursors.Hand, UseVisualStyleBackColor = false
        };
        b.FlatAppearance.BorderColor = Color.Black;
        b.FlatAppearance.BorderSize = 1;
        b.FlatAppearance.MouseOverBackColor = Hover;
        b.FlatAppearance.MouseDownBackColor = Color.FromArgb(215, 215, 215);
        b.Click += onClick;
        return b;
    }

    public static Label Lbl(string text) => new()
    {
        Text = text, AutoSize = true, Font = FB, ForeColor = Color.Black, Margin = new Padding(0, 12, 0, 4)
    };

    public static Label Note(string text) => new()
    {
        Text = text, AutoSize = true, Font = F, ForeColor = Color.Black,
        MaximumSize = new Size(860, 0), Margin = new Padding(0, 2, 0, 6)
    };

    public static TextBox Txt(bool readOnly = false, bool mono = true)
    {
        var t = new TextBox
        {
            Multiline = true, ReadOnly = readOnly, Font = mono ? FM : F, ForeColor = Color.Black,
            BorderStyle = BorderStyle.FixedSingle, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill
        };
        t.BackColor = Color.White;
        return t;
    }

    public static FlowLayoutPanel Row(params Control[] items)
    {
        var p = new FlowLayoutPanel { AutoSize = true, WrapContents = true, BackColor = Color.White, Margin = new Padding(0) };
        p.Controls.AddRange(items);
        return p;
    }

    /// <summary>Xếp dọc: h &lt;= 0 là tự co theo nội dung, h &gt; 0 là phần trăm chiều cao còn lại.</summary>
    public static TableLayoutPanel Stack(params (Control c, float h)[] rows)
    {
        var t = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = rows.Length,
            BackColor = Color.White, Padding = new Padding(28, 22, 28, 22)
        };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        foreach (var (c, h) in rows)
        {
            t.RowStyles.Add(h <= 0 ? new RowStyle(SizeType.AutoSize) : new RowStyle(SizeType.Percent, h));
            c.Dock = DockStyle.Fill;
            t.Controls.Add(c);
        }
        return t;
    }

    public static ListView Grid(params (string head, int width)[] cols)
    {
        var lv = new ListView
        {
            View = View.Details, FullRowSelect = true, GridLines = true, Font = F,
            BackColor = Color.White, ForeColor = Color.Black, BorderStyle = BorderStyle.FixedSingle,
            HeaderStyle = ColumnHeaderStyle.Nonclickable
        };
        foreach (var (h, w) in cols) lv.Columns.Add(h, w);
        return lv;
    }

    public static void Info(string m) => MessageBox.Show(m, "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
    public static void Error(string m) => MessageBox.Show(m, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);

    /// <summary>Khung ứng dụng: thanh điều hướng bên trái, nội dung bên phải. Trả về nhãn trạng thái ở chân thanh bên.</summary>
    public static Label Shell(Form f, string brand, string sub, params (string name, Control page)[] pages)
    {
        f.BackColor = Color.White; f.ForeColor = Color.Black; f.Font = F;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Color.White };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var side = new Panel { Dock = DockStyle.Fill, BackColor = Color.White };
        side.Paint += (_, e) => e.Graphics.DrawLine(Pens.Black, side.Width - 1, 0, side.Width - 1, side.Height);
        var content = new Panel { Dock = DockStyle.Fill, BackColor = Color.White };

        side.Controls.Add(new Label { Text = brand, Font = FT, AutoSize = true, Location = new Point(22, 22) });
        side.Controls.Add(new Label { Text = sub, Font = F, AutoSize = true, Location = new Point(25, 66) });

        var navs = new List<Button>();
        void Select(int idx)
        {
            for (int j = 0; j < pages.Length; j++)
            {
                pages[j].page.Visible = j == idx;
                navs[j].BackColor = j == idx ? Active : Color.White;
                navs[j].Font = j == idx ? FB : F;
            }
        }

        int y = 112;
        for (int i = 0; i < pages.Length; i++)
        {
            int idx = i;
            var b = new Button
            {
                Text = $"   {i + 1:D2}    {pages[i].name}", TextAlign = ContentAlignment.MiddleLeft,
                Size = new Size(249, 46), Location = new Point(0, y), Font = F,
                FlatStyle = FlatStyle.Flat, BackColor = Color.White, ForeColor = Color.Black,
                Cursor = Cursors.Hand, UseVisualStyleBackColor = false
            };
            b.FlatAppearance.BorderSize = 0;
            b.FlatAppearance.MouseOverBackColor = Hover;
            b.Click += (_, _) => Select(idx);
            navs.Add(b);
            side.Controls.Add(b);
            pages[i].page.Dock = DockStyle.Fill;
            content.Controls.Add(pages[i].page);
            y += 48;
        }

        var status = new Label
        {
            AutoSize = false, Size = new Size(220, 64), Font = F, ForeColor = Color.Black,
            Location = new Point(24, f.ClientSize.Height - 86), Anchor = AnchorStyles.Bottom | AnchorStyles.Left
        };
        side.Controls.Add(status);

        root.Controls.Add(side, 0, 0);
        root.Controls.Add(content, 1, 0);
        f.Controls.Add(root);
        Select(0);
        return status;
    }
}

static class UiExt
{
    /// <summary>Một ô có tiêu đề phía trên và điều khiển bên dưới.</summary>
    public static TableLayoutPanel Pane(string title, Control c)
    {
        var t = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = Color.White, Margin = new Padding(0, 0, 12, 0)
        };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var l = Ui.Lbl(title); l.Dock = DockStyle.Fill;
        c.Dock = DockStyle.Fill;
        t.Controls.Add(l, 0, 0);
        t.Controls.Add(c, 0, 1);
        return t;
    }

    /// <summary>Chia ngang đều nhau.</summary>
    public static TableLayoutPanel Cols(params Control[] items)
    {
        var t = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = items.Length, RowCount = 1, BackColor = Color.White
        };
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        for (int i = 0; i < items.Length; i++)
        {
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / items.Length));
            items[i].Dock = DockStyle.Fill;
            t.Controls.Add(items[i], i, 0);
        }
        return t;
    }
}

// ===== MainForm.cs =====
public class MainForm : Form
{
    RSA? pubKey, privKey;
    Label sideStatus = null!;

    // 01 Khóa
    readonly ComboBox cboBits = Combo(110, "1024 bit", "2048 bit", "3072 bit", "4096 bit");
    readonly ComboBox cboFmt = Combo(250, "PKCS#1 (RSA ... KEY)", "PKCS#8 / SPKI (... KEY)");
    readonly TextBox txtPubPem = Ui.Txt(true);
    readonly TextBox txtPrivPem = Ui.Txt(true);

    // 02 Cấu trúc PEM
    readonly TextBox txtPemIn = Ui.Txt(false);
    readonly TextBox txtHexDump = Ui.Txt(true);
    readonly TextBox txtTree = Ui.Txt(true);
    readonly Label lblPemInfo = Ui.Note("Chưa nạp PEM.");

    // 03 Nhập khóa
    readonly TextBox txtImport = Ui.Txt(true);

    // 04 Mã hóa
    readonly TextBox txtData = Ui.Txt(false, false);
    readonly CheckBox chkB64 = new() { Text = "Dữ liệu nhập là Base64", AutoSize = true, Font = Ui.F, Margin = new Padding(6, 16, 12, 6) };
    readonly Label lblCount = new() { AutoSize = true, Font = Ui.FB, Margin = new Padding(6, 16, 0, 6) };
    readonly TextBox txtCipherOut = Ui.Txt(true);
    byte[]? lastPlain;

    // 05 Giải mã
    readonly TextBox txtCipherIn = Ui.Txt(false);
    readonly TextBox txtOrig = Ui.Txt(false);
    readonly TextBox txtDecB64 = Ui.Txt(true);
    readonly TextBox txtDecText = Ui.Txt(true, false);
    readonly Label lblCmp = new() { AutoSize = true, Font = Ui.FB, Margin = new Padding(0, 6, 0, 6) };

    // 06 Hiệu năng
    readonly NumericUpDown nudMs = new() { Minimum = 200, Maximum = 5000, Value = 700, Increment = 100, Width = 90, Font = Ui.F, Margin = new Padding(0, 10, 10, 6) };
    readonly ListView lvBench = Ui.Grid(("Khóa", 70), ("Phép toán", 270), ("Số mũ dùng", 130), ("Số lần", 80),
                                         ("Tổng (ms)", 90), ("TB (ms/lần)", 100), ("Lần/giây", 90));
    readonly TextBox txtBenchSum = Ui.Txt(true, false);
    readonly Label lblBench = Ui.Note("Sẵn sàng.");
    Button bBench = null!;

    // 07 SHA-256
    readonly TextBox txtHashIn = Ui.Txt(false, false);
    readonly RichTextBox rtbNew = Rtb();
    readonly RichTextBox rtbOld = Rtb();
    readonly Label lblDiff = new() { AutoSize = true, Font = Ui.FB, Margin = new Padding(0, 6, 0, 6) };
    readonly TextBox txtAva = Ui.Txt(true, false);
    byte[]? curHash;
    bool settingText;

    // 08 Chữ ký số
    readonly ComboBox cboSign = Combo(430, "PKCS#1 v1.5 (xác định)", "RSA-PSS (salt ngẫu nhiên)", "PKCS#1 v1.5 + nonce ngẫu nhiên");
    readonly TextBox txtSignData = Ui.Txt(false, false);
    readonly TextBox txtSigOut = Ui.Txt(true);
    readonly List<byte[]> sigs = new();
    SignMode sigMode;
    byte[] sigData = Array.Empty<byte>();

    public MainForm()
    {
        Text = "RSA Lab – Bài 2";
        ClientSize = new Size(1280, 820);
        MinimumSize = new Size(1180, 760);
        StartPosition = FormStartPosition.CenterScreen;

        cboBits.SelectedIndex = 1;
        cboFmt.SelectedIndex = 1;
        cboSign.SelectedIndex = 0;

        sideStatus = Ui.Shell(this, "RSA Lab", "Bất đối xứng & chữ ký số",
            ("Sinh khóa", PageKeys()),
            ("Cấu trúc PEM", PagePem()),
            ("Nhập khóa", PageImport()),
            ("Mã hóa", PageEncrypt()),
            ("Giải mã", PageDecrypt()),
            ("Hiệu năng", PageBench()),
            ("Băm SHA-256", PageHash()),
            ("Chữ ký số", PageSign()));
        RefreshStatus();
    }

    // ---------- tiện ích ----------
    static ComboBox Combo(int w, params string[] items)
    {
        var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = w, Font = Ui.F, Margin = new Padding(0, 10, 12, 6) };
        c.Items.AddRange(items);
        return c;
    }

    static RichTextBox Rtb() => new()
    {
        ReadOnly = true, Font = new Font("Consolas", 13f), BackColor = Color.White, ForeColor = Color.Black,
        BorderStyle = BorderStyle.FixedSingle, ScrollBars = RichTextBoxScrollBars.None, Height = 62
    };

    static Label Title(string t) => new() { Text = t, Font = Ui.FT, AutoSize = true };

    void RefreshStatus()
    {
        string pu = pubKey == null ? "chưa có" : $"{pubKey.KeySize} bit";
        string pr = privKey == null ? "chưa có" : $"{privKey.KeySize} bit";
        sideStatus.Text = $"Public : {pu}\nPrivate: {pr}";
    }

    bool NeedPub() { if (pubKey != null) return true; Ui.Error("Chưa có khóa công khai. Hãy sinh khóa (01) hoặc nhập PEM công khai (03)."); return false; }
    bool NeedPriv() { if (privKey != null) return true; Ui.Error("Chưa có khóa riêng tư. Hãy sinh khóa (01) hoặc nhập PEM riêng tư (03)."); return false; }

    void SetPair(RSA full)
    {
        privKey?.Dispose(); pubKey?.Dispose();
        privKey = full;
        pubKey = RsaCore.PublicOnly(full);
        RefreshStatus();
    }

    static string ReadPemFile(string title)
    {
        using var d = new OpenFileDialog { Title = title, Filter = "Tệp PEM (*.pem)|*.pem|Tất cả (*.*)|*.*" };
        return d.ShowDialog() == DialogResult.OK ? File.ReadAllText(d.FileName) : "";
    }

    // ================= 01 Sinh khóa =================
    Control PageKeys()
    {
        var row = Ui.Row(cboBits, cboFmt, Ui.Btn("Sinh cặp khóa", OnGen, 160), Ui.Btn("Xuất PEM ra thư mục", OnExport, 200));
        return Ui.Stack(
            (Title("Sinh cặp khóa RSA"), 0),
            (Ui.Note("Cặp khóa gồm khóa công khai (n, e) và khóa riêng tư (n, d, p, q ...). Xuất ra hai tệp public.pem và private.pem."), 0),
            (row, 0),
            (UiExt.Cols(UiExt.Pane("Khóa công khai (public.pem)", txtPubPem), UiExt.Pane("Khóa riêng tư (private.pem)", txtPrivPem)), 100));
    }

    async void OnGen(object? s, EventArgs e)
    {
        int bits = int.Parse(cboBits.Text.Split(' ')[0]);
        bool p1 = cboFmt.SelectedIndex == 0;
        sideStatus.Text = "Đang sinh khóa...";
        try
        {
            var rsa = await Task.Run(() => RsaCore.Generate(bits));
            SetPair(rsa);
            txtPubPem.Text = RsaCore.PublicPem(rsa, p1);
            txtPrivPem.Text = RsaCore.PrivatePem(rsa, p1);
        }
        catch (Exception ex) { Ui.Error(ex.Message); RefreshStatus(); }
    }

    void OnExport(object? s, EventArgs e)
    {
        if (txtPubPem.Text.Length == 0) { Ui.Error("Hãy sinh cặp khóa trước."); return; }
        using var d = new FolderBrowserDialog { Description = "Chọn thư mục lưu public.pem và private.pem" };
        if (d.ShowDialog() != DialogResult.OK) return;
        try
        {
            File.WriteAllText(Path.Combine(d.SelectedPath, "public.pem"), txtPubPem.Text);
            File.WriteAllText(Path.Combine(d.SelectedPath, "private.pem"), txtPrivPem.Text);
            Ui.Info("Đã xuất public.pem và private.pem vào:\n" + d.SelectedPath);
        }
        catch (Exception ex) { Ui.Error(ex.Message); }
    }

    // ================= 02 Cấu trúc PEM =================
    Control PagePem()
    {
        var row = Ui.Row(
            Ui.Btn("Mở tệp PEM", (_, _) => { var t = ReadPemFile("Chọn tệp PEM"); if (t.Length > 0) Analyze(t); }, 150),
            Ui.Btn("Dùng public hiện tại", (_, _) => { if (txtPubPem.Text.Length > 0) Analyze(txtPubPem.Text); else Ui.Error("Chưa có PEM công khai."); }, 200),
            Ui.Btn("Dùng private hiện tại", (_, _) => { if (txtPrivPem.Text.Length > 0) Analyze(txtPrivPem.Text); else Ui.Error("Chưa có PEM riêng tư."); }, 200),
            Ui.Btn("Phân tích", (_, _) => Analyze(txtPemIn.Text), 130));
        return Ui.Stack(
            (Title("Cấu trúc tệp PEM"), 0),
            (Ui.Note("PEM = dòng BEGIN + Base64 của dữ liệu DER + dòng END. DER là chuỗi các khối TLV: Tag (loại) - Length (độ dài) - Value (giá trị)."), 0),
            (row, 0), (lblPemInfo, 0),
            (UiExt.Pane("Nội dung PEM", txtPemIn), 22),
            (UiExt.Cols(UiExt.Pane("Byte DER (hex)", txtHexDump), UiExt.Pane("Ý nghĩa từng khối", txtTree)), 60));
    }

    void Analyze(string pem)
    {
        try
        {
            txtPemIn.Text = pem.Trim();
            var (label, der) = Asn1.PemToDer(pem);
            var root = Asn1.Parse(der);
            lblPemInfo.Text = $"Nhãn: {label}   |   DER: {der.Length} byte   |   Khối gốc: SEQUENCE dài {root.Length} byte (+{root.HeaderLen} byte tiêu đề)";
            txtHexDump.Text = Asn1.HexDump(der);
            txtTree.Text = Asn1.Dump(der, root);
        }
        catch (Exception ex) { Ui.Error("Không phân tích được PEM: " + ex.Message); }
    }

    // ================= 03 Nhập khóa =================
    Control PageImport()
    {
        var row = Ui.Row(Ui.Btn("Nhập PEM công khai", (_, _) => ImportPem(false), 200),
                         Ui.Btn("Nhập PEM riêng tư", (_, _) => ImportPem(true), 200));
        return Ui.Stack(
            (Title("Nhập khóa từ tệp PEM"), 0),
            (Ui.Note("Công khai cho n và e. Riêng tư cho n, e, d, p, q, dP, dQ, qInv. Khóa nhập vào được dùng cho các trang mã hóa, giải mã, chữ ký."), 0),
            (row, 0),
            (txtImport, 100));
    }

    void ImportPem(bool wantPrivate)
    {
        string pem = ReadPemFile(wantPrivate ? "Chọn PEM riêng tư" : "Chọn PEM công khai");
        if (pem.Length == 0) return;
        try
        {
            var rsa = RsaCore.ImportPem(pem, out bool isPrivate);
            if (isPrivate != wantPrivate)
            {
                rsa.Dispose();
                Ui.Error(wantPrivate ? "Tệp này là khóa công khai, không phải khóa riêng tư." : "Tệp này là khóa riêng tư, hãy dùng nút nhập PEM riêng tư.");
                return;
            }
            if (isPrivate) SetPair(rsa);
            else { pubKey?.Dispose(); pubKey = rsa; RefreshStatus(); }
            txtImport.Text = RsaCore.Describe(rsa, isPrivate);
        }
        catch (Exception ex) { Ui.Error("Không nhập được PEM: " + ex.Message); }
    }

    // ================= 04 Mã hóa =================
    Control PageEncrypt()
    {
        txtData.Text = "Khóa AES bí mật cần gửi";
        txtData.TextChanged += (_, _) => UpdateCount();
        chkB64.CheckedChanged += (_, _) => UpdateCount();
        var row1 = Ui.Row(Ui.Btn("Nhập PEM công khai", (_, _) => ImportPem(false), 200),
                          Ui.Btn("Sinh khóa AES-256 (32 byte)", OnMakeAes, 240), chkB64, lblCount);
        var row2 = Ui.Row(Ui.Btn("Mã hóa", OnEncrypt, 150), Ui.Btn("Lưu bản mã ra tệp", OnSaveCipher, 190));
        UpdateCount();
        return Ui.Stack(
            (Title("Mã hóa bằng khóa công khai"), 0),
            (Ui.Note("OAEP-SHA256: khóa 2048 bit mã hóa tối đa 190 byte. Khóa AES-256 là 32 byte nên vừa; bản mã luôn dài 256 byte và khác nhau mỗi lần mã hóa."), 0),
            (row1, 0),
            (Ui.Lbl("Dữ liệu cần mã hóa"), 0), (txtData, 25),
            (row2, 0),
            (Ui.Lbl("Bản mã (Base64)"), 0), (txtCipherOut, 40));
    }

    byte[] PlainBytes() => chkB64.Checked ? Convert.FromBase64String(txtData.Text.Trim()) : Encoding.UTF8.GetBytes(txtData.Text);

    void UpdateCount()
    {
        try
        {
            int n = PlainBytes().Length;
            int max = pubKey != null ? RsaCore.MaxBytes(pubKey) : 190;
            lblCount.Text = $"{n} / {max} byte";
        }
        catch (FormatException) { lblCount.Text = "Base64 không hợp lệ"; }
    }

    void OnMakeAes(object? s, EventArgs e)
    {
        txtData.Text = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        chkB64.Checked = true;
    }

    void OnEncrypt(object? s, EventArgs e)
    {
        if (!NeedPub()) return;
        try
        {
            byte[] plain = PlainBytes();
            byte[] c = RsaCore.Encrypt(pubKey!, plain);
            lastPlain = plain;
            txtCipherOut.Text = Convert.ToBase64String(c);
            txtOrig.Text = Convert.ToBase64String(plain);
        }
        catch (Exception ex) { Ui.Error(ex.Message); }
    }

    void OnSaveCipher(object? s, EventArgs e)
    {
        if (txtCipherOut.Text.Length == 0) { Ui.Error("Chưa có bản mã."); return; }
        using var d = new SaveFileDialog { FileName = "cipher.b64", Filter = "Base64 (*.b64;*.txt)|*.b64;*.txt" };
        if (d.ShowDialog() != DialogResult.OK) return;
        try { File.WriteAllText(d.FileName, txtCipherOut.Text); Ui.Info("Đã lưu bản mã:\n" + d.FileName); }
        catch (Exception ex) { Ui.Error(ex.Message); }
    }

    // ================= 05 Giải mã =================
    Control PageDecrypt()
    {
        var row = Ui.Row(
            Ui.Btn("Nhập PEM riêng tư", (_, _) => ImportPem(true), 190),
            Ui.Btn("Mở tệp bản mã", OnOpenCipher, 170),
            Ui.Btn("Giải mã & so sánh", OnDecrypt, 190));
        return Ui.Stack(
            (Title("Giải mã & đối chiếu"), 0),
            (Ui.Note("Đầu vào: khóa riêng tư (PEM) và tệp bản mã Base64. Kết quả giải mã được so sánh từng byte với dữ liệu gốc (Base64)."), 0),
            (row, 0),
            (UiExt.Cols(UiExt.Pane("Bản mã (Base64)", txtCipherIn), UiExt.Pane("Dữ liệu gốc (Base64)", txtOrig)), 24),
            (UiExt.Cols(UiExt.Pane("Kết quả giải mã (Base64)", txtDecB64), UiExt.Pane("Kết quả giải mã (văn bản)", txtDecText)), 24),
            (lblCmp, 0));
    }

    void OnOpenCipher(object? s, EventArgs e)
    {
        using var d = new OpenFileDialog { Filter = "Base64 (*.b64;*.txt)|*.b64;*.txt|Tất cả (*.*)|*.*" };
        if (d.ShowDialog() == DialogResult.OK) txtCipherIn.Text = File.ReadAllText(d.FileName).Trim();
    }

    void OnDecrypt(object? s, EventArgs e)
    {
        if (!NeedPriv()) return;
        try
        {
            byte[] plain = RsaCore.Decrypt(privKey!, Convert.FromBase64String(txtCipherIn.Text.Trim()));
            txtDecB64.Text = Convert.ToBase64String(plain);
            txtDecText.Text = Encoding.UTF8.GetString(plain);
            byte[] orig = Convert.FromBase64String(txtOrig.Text.Trim());
            lblCmp.Text = plain.AsSpan().SequenceEqual(orig)
                ? $"KẾT QUẢ: GIỐNG NHAU ({plain.Length} / {orig.Length} byte trùng khớp)"
                : $"KẾT QUẢ: KHÁC NHAU (giải mã {plain.Length} byte, gốc {orig.Length} byte)";
        }
        catch (Exception ex) { Ui.Error("Giải mã thất bại: " + ex.Message); }
    }

    // ================= 06 Hiệu năng =================
    Control PageBench()
    {
        bBench = Ui.Btn("Chạy đo 1024 - 4096 bit", OnBench, 230);
        var lbl = new Label { Text = "Mỗi phép đo chạy (ms):", AutoSize = true, Font = Ui.F, Margin = new Padding(0, 18, 8, 6) };
        return Ui.Stack(
            (Title("Tốc độ mã hóa & giải mã"), 0),
            (Ui.Note("So sánh khóa công khai (e = 65537, rất nhỏ) với khóa riêng tư (d xấp xỉ bằng n). Phép lũy thừa modular thô cho thấy rõ chênh lệch."), 0),
            (Ui.Row(lbl, nudMs, bBench), 0),
            (lblBench, 0),
            (lvBench, 45),
            (UiExt.Pane("Nhận xét tự động", txtBenchSum), 25));
    }

    async void OnBench(object? s, EventArgs e)
    {
        bBench.Enabled = false;
        lvBench.Items.Clear();
        txtBenchSum.Clear();
        int ms = (int)nudMs.Value;
        var sum = new StringBuilder();
        try
        {
            foreach (int bits in new[] { 1024, 2048, 3072, 4096 })
            {
                lblBench.Text = $"Đang đo khóa {bits} bit...";
                var rows = await Task.Run(() => RsaCore.Benchmark(bits, ms));
                foreach (var r in rows)
                    lvBench.Items.Add(new ListViewItem(new[]
                    {
                        $"{r.Bits}", r.Op, r.Exponent, r.Count.ToString(),
                        r.TotalMs.ToString("F0"), r.AvgMs.ToString("F3"), r.PerSec.ToString("F1")
                    }));
                sum.AppendLine($"Khóa {bits} bit: giải mã (d) chậm hơn mã hóa (e) {rows[1].AvgMs / rows[0].AvgMs:F1} lần; " +
                               $"lũy thừa thô m^d chậm hơn m^e {rows[3].AvgMs / rows[2].AvgMs:F0} lần.");
            }
            txtBenchSum.Text = sum.ToString();
            lblBench.Text = "Hoàn tất.";
        }
        catch (Exception ex) { Ui.Error(ex.Message); }
        finally { bBench.Enabled = true; }
    }

    // ================= 07 SHA-256 =================
    Control PageHash()
    {
        txtHashIn.TextChanged += (_, _) => OnHashChanged();
        var row = Ui.Row(Ui.Btn("Đổi 1 ký tự cuối", OnTweak, 180), Ui.Btn("Thử 1000 lần đổi 1 bit", OnAvalanche, 220));
        settingText = true;
        txtHashIn.Text = "Xin chao";
        settingText = false;
        curHash = RsaCore.Sha256(txtHashIn.Text);
        Load += (_, _) => ShowHash(rtbNew, curHash!, null);
        return Ui.Stack(
            (Title("Băm SHA-256"), 0),
            (Ui.Note("Gõ vào ô dưới: mỗi lần thay đổi, hash mới được so với hash ngay trước đó. Ký tự khác nhau hiện nền đen chữ trắng."), 0),
            (txtHashIn, 20),
            (row, 0),
            (Ui.Lbl("Hash hiện tại"), 0), (rtbNew, 0),
            (Ui.Lbl("Hash trước đó"), 0), (rtbOld, 0),
            (lblDiff, 0),
            (UiExt.Pane("Thống kê hiệu ứng thác đổ", txtAva), 25));
    }

    void OnHashChanged()
    {
        if (settingText) return;
        byte[] old = curHash ?? RsaCore.Sha256("");
        curHash = RsaCore.Sha256(txtHashIn.Text);
        ShowHash(rtbNew, curHash, old);
        ShowHash(rtbOld, old, curHash);
        int bits = RsaCore.BitDiff(old, curHash);
        int chars = 0;
        string a = Convert.ToHexString(old), b = Convert.ToHexString(curHash);
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) chars++;
        lblDiff.Text = $"Khác nhau: {bits} / 256 bit ({bits / 2.56:F1}%)   |   {chars} / 64 ký tự hex";
    }

    static void ShowHash(RichTextBox box, byte[] hash, byte[]? other)
    {
        string h = Convert.ToHexString(hash);
        string? o = other == null ? null : Convert.ToHexString(other);
        box.Clear();
        for (int i = 0; i < h.Length; i++)
        {
            bool diff = o != null && h[i] != o[i];
            box.SelectionStart = box.TextLength;
            box.SelectionLength = 0;
            box.SelectionBackColor = diff ? Color.Black : Color.White;
            box.SelectionColor = diff ? Color.White : Color.Black;
            box.AppendText(h[i].ToString());
            if (i == 31) box.AppendText("\n");
        }
    }

    void OnTweak(object? s, EventArgs e)
    {
        string t = txtHashIn.Text;
        txtHashIn.Text = t.Length == 0 ? "a" : t[..^1] + (char)(t[^1] + 1);
    }

    void OnAvalanche(object? s, EventArgs e)
    {
        var (mean, min, max) = RsaCore.Avalanche(1000);
        txtAva.Text = $"1000 thông điệp ngẫu nhiên 64 byte, mỗi thông điệp chỉ đổi đúng 1 bit đầu vào:\r\n" +
                      $"- Trung bình đổi {mean:F2} / 256 bit hash ({mean / 2.56:F1}%)\r\n" +
                      $"- Ít nhất {min} bit, nhiều nhất {max} bit\r\n" +
                      $"- Kỳ vọng lý tưởng: 128 bit (50%)";
    }

    // ================= 08 Chữ ký số =================
    Control PageSign()
    {
        txtSignData.Text = "Hợp đồng số 01/2026 - bên A chuyển cho bên B 100.000.000 VND";
        var row1 = Ui.Row(cboSign);
        var row2 = Ui.Row(
            Ui.Btn("Ký 5 lần", OnSign, 130),
            Ui.Btn("Xác thực tất cả", OnVerify, 170),
            Ui.Btn("Xác thực sau khi sửa dữ liệu", OnVerifyTampered, 270));
        return Ui.Stack(
            (Title("Chữ ký số"), 0),
            (Ui.Note("Chữ ký = RSA(khóa riêng tư) áp lên SHA-256 của dữ liệu. Cùng dữ liệu, cùng khóa nhưng mỗi lần ký cho chữ ký khác nhau khi dùng PSS hoặc nonce."), 0),
            (Ui.Lbl("Dữ liệu cần ký"), 0), (txtSignData, 18),
            (Ui.Lbl("Phương pháp ký"), 0), (row1, 0), (row2, 0),
            (UiExt.Pane("Kết quả", txtSigOut), 50));
    }

    void OnSign(object? s, EventArgs e)
    {
        if (!NeedPriv()) return;
        try
        {
            sigMode = (SignMode)cboSign.SelectedIndex;
            sigData = Encoding.UTF8.GetBytes(txtSignData.Text);
            sigs.Clear();
            var sb = new StringBuilder();
            sb.AppendLine($"SHA-256 dữ liệu: {Convert.ToHexString(SHA256.HashData(sigData))}");
            sb.AppendLine();
            for (int i = 1; i <= 5; i++)
            {
                byte[] sg = RsaCore.Sign(privKey!, sigData, sigMode);
                sigs.Add(sg);
                string b64 = Convert.ToBase64String(sg);
                sb.AppendLine($"Lần {i}: {b64[..48]}...{b64[^12..]}   (SHA-256 chữ ký: {Convert.ToHexString(SHA256.HashData(sg))[..12]})");
            }
            int distinct = sigs.Select(Convert.ToBase64String).Distinct().Count();
            sb.AppendLine();
            sb.AppendLine($"Số chữ ký khác nhau: {distinct} / 5");
            txtSigOut.Text = sb.ToString();
        }
        catch (Exception ex) { Ui.Error(ex.Message); }
    }

    void OnVerify(object? s, EventArgs e)
    {
        if (sigs.Count == 0) { Ui.Error("Hãy ký trước."); return; }
        if (!NeedPub()) return;
        var sb = new StringBuilder(txtSigOut.Text).AppendLine().AppendLine("Xác thực bằng khóa công khai, dữ liệu gốc:");
        for (int i = 0; i < sigs.Count; i++)
            sb.AppendLine($"Lần {i + 1}: {(RsaCore.Verify(pubKey!, sigData, sigs[i], sigMode) ? "HỢP LỆ" : "KHÔNG HỢP LỆ")}");
        txtSigOut.Text = sb.ToString();
    }

    void OnVerifyTampered(object? s, EventArgs e)
    {
        if (sigs.Count == 0) { Ui.Error("Hãy ký trước."); return; }
        if (!NeedPub()) return;
        byte[] bad = (byte[])sigData.Clone();
        if (bad.Length == 0) return;
        bad[^1] ^= 1;
        var sb = new StringBuilder(txtSigOut.Text).AppendLine().AppendLine("Xác thực với dữ liệu đã bị sửa 1 bit:");
        for (int i = 0; i < sigs.Count; i++)
            sb.AppendLine($"Lần {i + 1}: {(RsaCore.Verify(pubKey!, bad, sigs[i], sigMode) ? "HỢP LỆ" : "KHÔNG HỢP LỆ")}");
        txtSigOut.Text = sb.ToString();
    }
}
