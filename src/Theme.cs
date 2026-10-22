using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
namespace Cogitator
{
    static class Theme
    {
        public static readonly Color Bg = Color.FromArgb(4, 9, 5);
        public static readonly Color BgLog = Color.FromArgb(3, 7, 4);
        public static readonly Color Green = Color.FromArgb(84, 238, 112);
        public static readonly Color GreenMid = Color.FromArgb(52, 170, 78);
        public static readonly Color GreenDim = Color.FromArgb(30, 104, 48);
        public static readonly Color GreenDark = Color.FromArgb(10, 34, 16);
        public static readonly Color Orange = Color.FromArgb(255, 122, 40);
        public static readonly Color OrangeDim = Color.FromArgb(150, 66, 22);
        public static readonly Color Red = Color.FromArgb(255, 70, 52);
        public static readonly Color Amber = Color.FromArgb(255, 150, 46);
        public static readonly Color Text = Color.FromArgb(176, 236, 186);

        static readonly Dictionary<string, Font> cache = new Dictionary<string, Font>();

        [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] static extern int AddFontResourceEx(string name, uint fl, IntPtr res);
        static System.Drawing.Text.PrivateFontCollection pfc;
        static FontFamily pixFam;
        public static string FontKey = "fixedsys";
        public static bool Pixel { get { return pixFam != null; } }

        public static void InitFont(string key)
        {
            FontKey = key ?? "consolas";
            string res = FontKey == "fixedsys" ? "FSEX.ttf" : FontKey == "dos" ? "CogDOS.ttf" : null;
            if (res == null) return;
            string sysName = FontKey == "fixedsys" ? "Fixedsys Excelsior" : "Cogitator DOS VGA";
            try { using (var t = new Font(sysName, 10f)) if (t.Name == sysName) { var h = t.Height; pixFam = new FontFamily(sysName); return; } } catch { }
            try
            {
                string dir = Path.Combine(Path.GetTempPath(), "Cogitator");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, res);
                using (var st = Assembly.GetExecutingAssembly().GetManifestResourceStream(res))
                {
                    var data = new byte[st.Length]; st.Read(data, 0, data.Length);
                    if (!File.Exists(path) || new FileInfo(path).Length != data.Length) File.WriteAllBytes(path, data);
                }
                try { AddFontResourceEx(path, 0x10, IntPtr.Zero); } catch { }
                pfc = new System.Drawing.Text.PrivateFontCollection();
                pfc.AddFontFile(path);
                pixFam = pfc.Families[0];
                using (var test = new Font(pixFam, 10f)) { var h = test.Height; }
            }
            catch { pixFam = null; FontKey = "consolas"; }
        }

        static Font PixelFont(float size, FontStyle st)
        {
            float px = size * 96f / 72f;
            if (px < 10.5f) return Try(new[] { "Consolas", "Lucida Console", "Courier New" }, size, st);
            float target = px >= 26f ? 32f : 16f;
            try { return new Font(pixFam, target, FontStyle.Regular, GraphicsUnit.Pixel); } catch { return Try(new[] { "Consolas" }, size, st); }
        }

        public static Font Mono(float size, FontStyle st)
        {
            string key = "m" + size + st;
            Font f;
            if (cache.TryGetValue(key, out f)) return f;
            f = Pixel ? PixelFont(size, st)
              : FontKey == "courier" ? Try(new[] { "Courier New", "Courier", "Consolas" }, size, st)
              : Try(new[] { "Consolas", "Lucida Console", "Courier New" }, size, st);
            cache[key] = f;
            return f;
        }

        public static Font Title(float size)
        {
            string key = "t" + size;
            Font f;
            if (cache.TryGetValue(key, out f)) return f;
            f = Pixel ? PixelFont(size, FontStyle.Bold)
              : FontKey == "courier" ? Try(new[] { "Courier New", "Courier" }, size, FontStyle.Bold)
              : Try(new[] { "OCR A Extended", "Consolas", "Lucida Console" }, size, FontStyle.Bold);
            cache[key] = f;
            return f;
        }

        static Font Try(string[] names, float size, FontStyle st)
        {
            foreach (var n in names)
            {
                try { var f = new Font(n, size, st); if (f.Name == n) return f; f.Dispose(); } catch { }
            }
            return new Font(FontFamily.GenericMonospace, size, st);
        }

        public static void Prep(Graphics g)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
        }

        public static void Glow(Graphics g, string s, Font f, Color c, RectangleF r, StringFormat sf)
        {
            using (var b = new SolidBrush(Color.FromArgb(38, c)))
            {
                g.DrawString(s, f, b, new RectangleF(r.X - 1.5f, r.Y, r.Width, r.Height), sf);
                g.DrawString(s, f, b, new RectangleF(r.X + 1.5f, r.Y, r.Width, r.Height), sf);
                g.DrawString(s, f, b, new RectangleF(r.X, r.Y - 1.5f, r.Width, r.Height), sf);
                g.DrawString(s, f, b, new RectangleF(r.X, r.Y + 1.5f, r.Width, r.Height), sf);
            }
            using (var b = new SolidBrush(c)) g.DrawString(s, f, b, r, sf);
        }

        public static void Glow(Graphics g, string s, Font f, Color c, float x, float y)
        {
            Glow(g, s, f, c, new RectangleF(x, y, 4000, 400), StringFormat.GenericTypographic);
        }

        public static void Box(Graphics g, RectangleF r, Color c, float w = 1.5f)
        {
            using (var p = new Pen(Color.FromArgb(45, c), w + 3f)) g.DrawRectangle(p, r.X, r.Y, r.Width, r.Height);
            using (var p = new Pen(c, w)) g.DrawRectangle(p, r.X, r.Y, r.Width, r.Height);
        }

        public static void Line(Graphics g, Color c, float x1, float y1, float x2, float y2, float w = 1.5f)
        {
            using (var p = new Pen(Color.FromArgb(45, c), w + 3f)) g.DrawLine(p, x1, y1, x2, y2);
            using (var p = new Pen(c, w)) g.DrawLine(p, x1, y1, x2, y2);
        }

        public static void Cross(Graphics g, float x, float y, float arm, Color c)
        {
            float o = 3.5f;
            Line(g, c, x - arm, y - o, x + arm, y - o, 1.4f);
            Line(g, c, x - arm, y + o, x + arm, y + o, 1.4f);
            Line(g, c, x - o, y - arm, x - o, y + arm, 1.4f);
            Line(g, c, x + o, y - arm, x + o, y + arm, 1.4f);
        }

        public static void Scanlines(Graphics g, Rectangle r)
        {
            using (var b = new SolidBrush(Color.FromArgb(30, 0, 0, 0)))
                for (int y = r.Top; y < r.Bottom; y += 3) g.FillRectangle(b, r.Left, y, r.Width, 1);
        }

        static TextureBrush overlay;
        static TextureBrush OverlayBrush
        {
            get
            {
                if (overlay != null) return overlay;
                var bmp = new Bitmap(160, 159, PixelFormat.Format32bppPArgb);
                var rnd = new Random(4242);
                for (int y = 0; y < 159; y++)
                    for (int x = 0; x < 160; x++)
                    {
                        Color c = Color.Transparent;
                        double r = rnd.NextDouble();
                        if (r < 0.09) c = Color.FromArgb(rnd.Next(6, 15), 120, 255, 140);
                        else if (r < 0.12) c = Color.FromArgb(rnd.Next(12, 30), 0, 0, 0);
                        if (y % 3 == 0) c = Color.FromArgb(Math.Min(255, c.A + 60), 0, 0, 0);
                        else if (y % 3 == 1) c = Color.FromArgb(Math.Min(255, c.A + 30), 0, 0, 0);
                        if (c.A > 0) bmp.SetPixel(x, y, c);
                    }
                overlay = new TextureBrush(bmp, WrapMode.Tile);
                return overlay;
            }
        }

        public static void Overlay(Graphics g, Rectangle r, int ox, int oy)
        {
            var b = OverlayBrush;
            b.ResetTransform();
            b.TranslateTransform(ox, oy - oy % 3);
            var old = g.CompositingQuality;
            g.CompositingQuality = CompositingQuality.HighSpeed;
            g.FillRectangle(b, r);
            g.CompositingQuality = old;
        }

        static readonly Dictionary<Size, Bitmap> vignettes = new Dictionary<Size, Bitmap>();

        public static Bitmap VignetteBitmap(Size sz)
        {
            Bitmap bmp;
            if (vignettes.TryGetValue(sz, out bmp)) return bmp;
            if (vignettes.Count > 6) { foreach (var v in vignettes.Values) v.Dispose(); vignettes.Clear(); }
            bmp = new Bitmap(Math.Max(1, sz.Width), Math.Max(1, sz.Height), PixelFormat.Format32bppPArgb);
            using (var g = Graphics.FromImage(bmp))
            using (var gp = new GraphicsPath())
            {
                var r = new Rectangle(0, 0, sz.Width, sz.Height);
                gp.AddEllipse(RectangleF.Inflate(r, r.Width * 0.22f, r.Height * 0.32f));
                using (var pb = new PathGradientBrush(gp) { CenterColor = Color.FromArgb(0, 0, 0, 0), SurroundColors = new[] { Color.FromArgb(170, 0, 0, 0) }, FocusScales = new PointF(0.6f, 0.55f) })
                    g.FillRectangle(pb, r);
            }
            vignettes[sz] = bmp;
            return bmp;
        }

        static TextureBrush grain;
        static TextureBrush GrainBrush
        {
            get
            {
                if (grain != null) return grain;
                var bmp = new Bitmap(160, 160, PixelFormat.Format32bppArgb);
                var rnd = new Random(1337);
                for (int y = 0; y < 160; y++)
                    for (int x = 0; x < 160; x++)
                    {
                        double r = rnd.NextDouble();
                        if (r < 0.10) bmp.SetPixel(x, y, Color.FromArgb(rnd.Next(6, 16), 120, 255, 140));
                        else if (r < 0.14) bmp.SetPixel(x, y, Color.FromArgb(rnd.Next(14, 34), 0, 0, 0));
                    }
                grain = new TextureBrush(bmp, WrapMode.Tile);
                return grain;
            }
        }

        public static void PaintGrain(Graphics g, Rectangle r, int ox, int oy)
        {
            var b = GrainBrush;
            b.ResetTransform();
            b.TranslateTransform(ox, oy);
            g.FillRectangle(b, r);
        }

        public static void Vignette(Graphics g, Rectangle r)
        {
            if (r.Width < 10 || r.Height < 10) return;
            g.DrawImageUnscaled(VignetteBitmap(r.Size), r.X, r.Y);
        }

        public static PointF[] CogPoints(PointF c, float ro, float ri, int teeth, float angle)
        {
            int n = teeth * 4;
            var pts = new PointF[n];
            for (int i = 0; i < n; i++)
            {
                double a = 2 * Math.PI * i / n - Math.PI / 2 + angle;
                float r = (i % 4 == 0 || i % 4 == 1) ? ro : ri;
                pts[i] = new PointF(c.X + (float)(r * Math.Cos(a)), c.Y + (float)(r * Math.Sin(a)));
            }
            return pts;
        }

        public static StringFormat Center = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        public static StringFormat Left = new StringFormat { Alignment = StringAlignment.Near, LineAlignment = StringAlignment.Center };
        public static StringFormat Right = new StringFormat { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center };
    }
}
