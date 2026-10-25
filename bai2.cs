using System.Diagnostics;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;

namespace Bai1_AES;

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

// ===== AesCore.cs =====
/// <summary>Toàn bộ nghiệp vụ AES (không phụ thuộc giao diện).</summary>
public static class AesCore
{
    const int Block = 16;          // AES luôn xử lý khối 128 bit = 16 byte
    const int Chunk = 4 * 1024 * 1024; // đọc/ghi từng khối 4 MB để file hàng GB không tràn RAM

    // ---------- 1, 2, 3. Khóa ----------
    public static byte[] NewKey(int bits)
    {
        if (bits is not (128 or 192 or 256)) throw new ArgumentException("Độ dài khóa phải là 128, 192 hoặc 256 bit");
        return RandomNumberGenerator.GetBytes(bits / 8);
    }

    public static void SaveKey(string path, byte[] key) =>
        File.WriteAllText(path, Convert.ToBase64String(key));

    public static byte[] LoadKey(string path)
    {
        byte[] key;
        try { key = Convert.FromBase64String(File.ReadAllText(path).Trim()); }
        catch (FormatException) { throw new InvalidDataException("Tệp khóa không phải Base64 hợp lệ"); }
        if (key.Length is not (16 or 24 or 32))
            throw new InvalidDataException($"Khóa dài {key.Length} byte, AES chỉ nhận 16, 24 hoặc 32 byte");
        return key;
    }

    public static string Fingerprint(byte[] key) =>
        Convert.ToHexString(SHA256.HashData(key))[..16].ToLowerInvariant();

    // ---------- 4. Văn bản ----------
    // Định dạng bản mã: Base64( IV 16 byte || dữ liệu mã hóa ) – AES-CBC, đệm PKCS7
    public static string EncryptText(string plain, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(plain), aes.IV);
        byte[] all = new byte[Block + cipher.Length];
        aes.IV.CopyTo(all, 0);
        cipher.CopyTo(all, Block);
        return Convert.ToBase64String(all);
    }

    public static string DecryptText(string base64, byte[] key)
    {
        byte[] all = Convert.FromBase64String(base64.Trim());
        if (all.Length < Block * 2) throw new InvalidDataException("Bản mã quá ngắn");
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] iv = all[..Block];
        byte[] cipher = all[Block..];
        return Encoding.UTF8.GetString(aes.DecryptCbc(cipher, iv));
    }

    // ---------- 5. Tệp ----------
    // Định dạng tệp .enc: IV (16 byte) || dữ liệu mã hóa theo luồng
    public static void EncryptFile(string src, string dst, byte[] key, IProgress<double>? progress = null)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        fout.Write(aes.IV, 0, Block);
        using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
        Pump(fin, cs, fin.Length, progress);
        cs.FlushFinalBlock();
    }

    public static void DecryptFile(string src, string dst, byte[] key, IProgress<double>? progress = null)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        byte[] iv = new byte[Block];
        fin.ReadExactly(iv, 0, Block);
        aes.IV = iv;
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
        Pump(cs, fout, fin.Length, progress, useSourcePosition: fin);
    }

    static void Pump(Stream from, Stream to, long total, IProgress<double>? progress, Stream? useSourcePosition = null)
    {
        byte[] buf = new byte[Chunk];
        long done = 0;
        int n;
        while ((n = from.Read(buf, 0, buf.Length)) > 0)
        {
            to.Write(buf, 0, n);
            done += n;
            long pos = useSourcePosition?.Position ?? done;
            progress?.Report(total == 0 ? 1 : (double)pos / total);
        }
        progress?.Report(1);
    }

    // ---------- So sánh theo byte ----------
    public readonly record struct CompareResult(bool Equal, long SizeA, long SizeB, long FirstDiff);

    public static CompareResult CompareFiles(string a, string b, IProgress<double>? progress = null)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        if (fa.Length != fb.Length) return new(false, fa.Length, fb.Length, Math.Min(fa.Length, fb.Length));

        byte[] ba = new byte[Chunk], bb = new byte[Chunk];
        long pos = 0;
        while (pos < fa.Length)
        {
            int n = fa.Read(ba, 0, ba.Length);
            fb.ReadExactly(bb, 0, n);
            int k = ba.AsSpan(0, n).CommonPrefixLength(bb.AsSpan(0, n));
            if (k < n) return new(false, fa.Length, fb.Length, pos + k);
            pos += n;
            progress?.Report((double)pos / fa.Length);
        }
        progress?.Report(1);
        return new(true, fa.Length, fb.Length, -1);
    }

    // ---------- Tạo tệp thử nghiệm ----------
    public static void MakeTestFile(string path, long bytes, IProgress<double>? progress = null)
    {
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        byte[] buf = new byte[Chunk];
        var rnd = new Random(2026);
        long left = bytes;
        while (left > 0)
        {
            int n = (int)Math.Min(buf.Length, left);
            rnd.NextBytes(buf.AsSpan(0, n));
            fs.Write(buf, 0, n);
            left -= n;
            progress?.Report((double)(bytes - left) / bytes);
        }
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

// ===== MainForm.cs =====
public class MainForm : Form
{
    byte[]? key;

    // Trang 1: Khóa
    readonly ComboBox cboBits = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110, Font = Ui.F, Margin = new Padding(0, 10, 12, 6) };
    readonly TextBox txtB64 = Ui.Txt(true);
    readonly TextBox txtHex = Ui.Txt(true);
    readonly Label lblKeyInfo = Ui.Note("Chưa có khóa.");

    // Trang 2: Văn bản
    readonly TextBox txtPlain = Ui.Txt(false, false);
    readonly TextBox txtCipher = Ui.Txt(false);
    readonly TextBox txtBack = Ui.Txt(true, false);

    // Trang 3: Tệp
    readonly TextBox txtSrc = new() { ReadOnly = true, Font = Ui.F, Width = 560, BackColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Margin = new Padding(0, 10, 10, 6) };
    readonly NumericUpDown nudMb = new() { Minimum = 1, Maximum = 20000, Value = 1024, Width = 90, Font = Ui.F, Margin = new Padding(0, 10, 10, 6) };
    readonly ProgressBar bar = new() { Height = 14, Style = ProgressBarStyle.Continuous };
    readonly Label lblStatus = Ui.Note("Sẵn sàng.");
    readonly TextBox txtLog = Ui.Txt(true);
    readonly ListView lv = Ui.Grid(("Tệp", 150), ("Dung lượng (MB)", 120), ("Mã hóa (s)", 90), ("Giải mã (s)", 90),
                                    ("MB/s mã hóa", 100), ("MB/s giải mã", 105), ("So sánh byte", 100));
    readonly List<Button> busyButtons = new();
    Label sideStatus = null!;

    double encMs, decMs;

    public MainForm()
    {
        Text = "AES Lab – Bài 1";
        ClientSize = new Size(1180, 760);
        MinimumSize = new Size(1100, 700);
        StartPosition = FormStartPosition.CenterScreen;

        cboBits.Items.AddRange(new object[] { "128 bit", "192 bit", "256 bit" });
        cboBits.SelectedIndex = 2;

        sideStatus = Ui.Shell(this, "AES Lab", "Mã hóa đối xứng",
            ("Khóa", BuildKeyPage()),
            ("Văn bản", BuildTextPage()),
            ("Tệp tin", BuildFilePage()));
        sideStatus.Text = "Chưa có khóa";
    }

    // ================= Trang 1: Khóa =================
    Control BuildKeyPage()
    {
        var row = Ui.Row(cboBits,
            Ui.Btn("Sinh khóa", OnGen, 150),
            Ui.Btn("Lưu khóa ra tệp", OnSave, 170),
            Ui.Btn("Nhập khóa từ tệp", OnLoad, 170));
        var title = new Label { Text = "Khóa AES", Font = Ui.FT, AutoSize = true };
        return Ui.Stack(
            (title, 0),
            (Ui.Note("Một khóa duy nhất dùng cho cả mã hóa và giải mã. Khóa lưu dạng Base64 trong tệp .key."), 0),
            (row, 0),
            (Ui.Lbl("Khóa (Base64)"), 0), (txtB64, 22),
            (Ui.Lbl("Khóa (Hex)"), 0), (txtHex, 22),
            (lblKeyInfo, 0));
    }

    void OnGen(object? s, EventArgs e)
    {
        int bits = int.Parse(cboBits.Text.Split(' ')[0]);
        key = AesCore.NewKey(bits);
        ShowKey();
    }

    void OnSave(object? s, EventArgs e)
    {
        if (!NeedKey()) return;
        using var d = new SaveFileDialog { Filter = "Tệp khóa AES (*.key)|*.key", FileName = "aes.key" };
        if (d.ShowDialog() != DialogResult.OK) return;
        try { AesCore.SaveKey(d.FileName, key!); Ui.Info("Đã lưu khóa:\n" + d.FileName); }
        catch (Exception ex) { Ui.Error(ex.Message); }
    }

    void OnLoad(object? s, EventArgs e)
    {
        using var d = new OpenFileDialog { Filter = "Tệp khóa AES (*.key)|*.key|Tất cả (*.*)|*.*" };
        if (d.ShowDialog() != DialogResult.OK) return;
        try { key = AesCore.LoadKey(d.FileName); ShowKey(); }
        catch (Exception ex) { Ui.Error(ex.Message); }
    }

    void ShowKey()
    {
        txtB64.Text = Convert.ToBase64String(key!);
        txtHex.Text = Convert.ToHexString(key!).ToLowerInvariant();
        lblKeyInfo.Text = $"Độ dài: {key!.Length * 8} bit ({key.Length} byte)   |   Dấu vân tay SHA-256: {AesCore.Fingerprint(key)}";
        sideStatus.Text = $"Khóa {key.Length * 8} bit\nVân tay: {AesCore.Fingerprint(key)[..8]}";
    }

    bool NeedKey()
    {
        if (key != null) return true;
        Ui.Error("Chưa có khóa. Hãy sinh khóa hoặc nhập khóa từ tệp ở trang 01.");
        return false;
    }

    // ================= Trang 2: Văn bản =================
    Control BuildTextPage()
    {
        var title = new Label { Text = "Mã hóa văn bản", Font = Ui.FT, AutoSize = true };
        var row = Ui.Row(Ui.Btn("Mã hóa", OnEncText, 150), Ui.Btn("Giải mã", OnDecText, 150));
        txtPlain.Text = "Học phần An toàn và bảo mật thông tin – AES-CBC.";
        return Ui.Stack(
            (title, 0),
            (Ui.Note("Bản mã = Base64( IV 16 byte + dữ liệu mã hóa ). Mỗi lần mã hóa IV khác nhau nên bản mã luôn khác nhau."), 0),
            (Ui.Lbl("Văn bản gốc"), 0), (txtPlain, 22),
            (row, 0),
            (Ui.Lbl("Kết quả mã hóa (Base64)"), 0), (txtCipher, 22),
            (Ui.Lbl("Kết quả giải mã"), 0), (txtBack, 22));
    }

    void OnEncText(object? s, EventArgs e)
    {
        if (!NeedKey()) return;
        try { txtCipher.Text = AesCore.EncryptText(txtPlain.Text, key!); txtBack.Clear(); }
        catch (Exception ex) { Ui.Error(ex.Message); }
    }

    void OnDecText(object? s, EventArgs e)
    {
        if (!NeedKey()) return;
        try { txtBack.Text = AesCore.DecryptText(txtCipher.Text, key!); }
        catch (Exception ex) { Ui.Error("Giải mã thất bại: " + ex.Message); }
    }

    // ================= Trang 3: Tệp =================
    Control BuildFilePage()
    {
        var title = new Label { Text = "Mã hóa tệp & đo hiệu năng", Font = Ui.FT, AutoSize = true };

        var bPick = Ui.Btn("Chọn tệp nguồn", OnPick, 160);
        var bMake = Ui.Btn("Tạo tệp thử nghiệm", OnMake, 190);
        var bEnc = Ui.Btn("Mã hóa", (_, _) => _ = SafeRun(DoEnc), 130);
        var bDec = Ui.Btn("Giải mã", (_, _) => _ = SafeRun(DoDec), 130);
        var bCmp = Ui.Btn("So sánh byte", (_, _) => _ = SafeRun(DoCmp), 150);
        var bAll = Ui.Btn("Chạy toàn bộ", (_, _) => _ = SafeRun(DoAll), 150);
        busyButtons.AddRange(new[] { bPick, bMake, bEnc, bDec, bCmp, bAll });

        var rowSrc = Ui.Row(txtSrc, bPick);
        var lblMb = new Label { Text = "Dung lượng (MB):", AutoSize = true, Font = Ui.F, Margin = new Padding(0, 18, 8, 6) };
        var rowMake = Ui.Row(lblMb, nudMb, bMake);
        var rowRun = Ui.Row(bEnc, bDec, bCmp, bAll);

        return Ui.Stack(
            (title, 0),
            (Ui.Note("Mã hóa theo luồng từng khối 4 MB nên xử lý được tệp hàng GB mà không tốn RAM. Tệp .enc = IV (16 byte) + dữ liệu mã hóa; tệp giải mã lưu thành <tên>.dec."), 0),
            (rowSrc, 0), (rowMake, 0), (rowRun, 0),
            (bar, 0), (lblStatus, 0),
            (lv, 24), (txtLog, 24));
    }

    string EncPath => txtSrc.Text + ".enc";
    string DecPath => txtSrc.Text + ".dec";

    void OnPick(object? s, EventArgs e)
    {
        using var d = new OpenFileDialog();
        if (d.ShowDialog() == DialogResult.OK) txtSrc.Text = d.FileName;
    }

    async void OnMake(object? s, EventArgs e)
    {
        using var d = new SaveFileDialog { FileName = $"test_{nudMb.Value}MB.bin" };
        if (d.ShowDialog() != DialogResult.OK) return;
        string path = d.FileName;
        long bytes = (long)nudMb.Value * 1024 * 1024;
        try
        {
            var (_, ms) = await Timed("Đang tạo tệp thử nghiệm", p => { AesCore.MakeTestFile(path, bytes, p); return 0; });
            txtSrc.Text = path;
            Log($"Tạo tệp {nudMb.Value} MB trong {ms / 1000:F2} s: {path}");
        }
        catch (Exception ex) { Ui.Error(ex.Message); }
    }

    async Task SafeRun(Func<Task> job)
    {
        try { await job(); }
        catch (Exception ex) { Ui.Error(ex.Message); lblStatus.Text = "Lỗi: " + ex.Message; }
    }

    bool NeedSrc()
    {
        if (!NeedKey()) return false;
        if (File.Exists(txtSrc.Text)) return true;
        Ui.Error("Hãy chọn tệp nguồn hoặc tạo tệp thử nghiệm.");
        return false;
    }

    async Task<(T result, double ms)> Timed<T>(string title, Func<IProgress<double>, T> work)
    {
        SetBusy(true);
        bar.Value = 0;
        lblStatus.Text = title + "...";
        var prog = new Progress<double>(v => bar.Value = (int)Math.Clamp(v * 100, 0, 100));
        try
        {
            var sw = Stopwatch.StartNew();
            T r = await Task.Run(() => work(prog));
            sw.Stop();
            lblStatus.Text = $"{title}: xong sau {sw.Elapsed.TotalSeconds:F2} s";
            return (r, sw.Elapsed.TotalMilliseconds);
        }
        finally { SetBusy(false); }
    }

    void SetBusy(bool busy) { foreach (var b in busyButtons) b.Enabled = !busy; }

    static double Mb(long bytes) => bytes / 1048576.0;

    async Task DoEnc()
    {
        if (!NeedSrc()) return;
        string src = txtSrc.Text, dst = EncPath; var k = key!;
        var (_, ms) = await Timed("Mã hóa tệp", p => { AesCore.EncryptFile(src, dst, k, p); return 0; });
        encMs = ms;
        long a = new FileInfo(src).Length, b = new FileInfo(dst).Length;
        Log($"Mã hóa: {Mb(a):F1} MB -> {Mb(b):F1} MB trong {ms / 1000:F2} s ({Mb(a) / (ms / 1000):F1} MB/s)");
    }

    async Task DoDec()
    {
        if (!NeedSrc()) return;
        if (!File.Exists(EncPath)) { Ui.Error("Chưa có tệp .enc, hãy mã hóa trước."); return; }
        string src = EncPath, dst = DecPath; var k = key!;
        var (_, ms) = await Timed("Giải mã tệp", p => { AesCore.DecryptFile(src, dst, k, p); return 0; });
        decMs = ms;
        long a = new FileInfo(dst).Length;
        Log($"Giải mã: {Mb(a):F1} MB trong {ms / 1000:F2} s ({Mb(a) / (ms / 1000):F1} MB/s)");
    }

    async Task<AesCore.CompareResult?> DoCmp()
    {
        if (!NeedSrc()) return null;
        if (!File.Exists(DecPath)) { Ui.Error("Chưa có tệp giải mã, hãy giải mã trước."); return null; }
        string a = txtSrc.Text, b = DecPath;
        var (r, ms) = await Timed("So sánh byte", p => AesCore.CompareFiles(a, b, p));
        Log(r.Equal
            ? $"So sánh: GIỐNG NHAU hoàn toàn ({r.SizeA:N0} byte) – {ms / 1000:F2} s"
            : $"So sánh: KHÁC NHAU – kích thước {r.SizeA:N0} / {r.SizeB:N0} byte, lệch đầu tiên tại byte {r.FirstDiff:N0}");
        return r;
    }

    async Task DoAll()
    {
        if (!NeedSrc()) return;
        await DoEnc();
        await DoDec();
        var r = await DoCmp();
        if (r is null) return;
        double mb = Mb(r.Value.SizeA);
        var item = new ListViewItem(new[]
        {
            Path.GetFileName(txtSrc.Text), mb.ToString("F1"),
            (encMs / 1000).ToString("F2"), (decMs / 1000).ToString("F2"),
            (mb / (encMs / 1000)).ToString("F1"), (mb / (decMs / 1000)).ToString("F1"),
            r.Value.Equal ? "Giống nhau" : "Khác nhau"
        });
        lv.Items.Add(item);
    }

    void Log(string line) => txtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {line}{Environment.NewLine}");
}
