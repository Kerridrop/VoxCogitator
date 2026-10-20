using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SkiaSharp;

namespace System.Drawing
{
    public enum GraphicsUnit { World, Display, Pixel, Point, Inch, Document, Millimeter }
    public enum StringAlignment { Near, Center, Far }
    [Flags] public enum StringFormatFlags { NoWrap = 0x1000, NoClip = 0x4000, DirectionVertical = 0x2 }
    public enum StringTrimming { None, Character, Word, EllipsisCharacter, EllipsisWord, EllipsisPath }
    [Flags] public enum FontStyle { Regular = 0, Bold = 1, Italic = 2, Underline = 4, Strikeout = 8 }

    static class Px
    {
        public static float Size(float size, GraphicsUnit u) { return u == GraphicsUnit.Pixel ? size : size * 96f / 72f; }
    }

    public sealed class FontFamily
    {
        internal SKTypeface Face; public string Name;
        internal FontFamily(SKTypeface f, string n) { Face = f; Name = n; }
        public FontFamily(string name) { Name = name; Face = FontStore.Resolve(name, FontStyle.Regular); }
        public static FontFamily GenericMonospace { get { return new FontFamily(FontStore.Mono); } }
        internal FontFamily(SKTypeface f) { Face = f; Name = f != null ? f.FamilyName : FontStore.Mono; }
    }

    static class FontStore
    {
        public const string Mono = "__mono__";
        static readonly Dictionary<string, SKTypeface> reg = new Dictionary<string, SKTypeface>(StringComparer.OrdinalIgnoreCase);
        public static void Register(SKTypeface t) { if (t != null) reg[t.FamilyName] = t; }
        public static SKTypeface Resolve(string name, FontStyle st)
        {
            if (name == Mono) return SKTypeface.FromFamilyName("monospace", st.HasFlag(FontStyle.Bold) ? SKFontStyleWeight.Bold : SKFontStyleWeight.Normal, SKFontStyleWidth.Normal, st.HasFlag(FontStyle.Italic) ? SKFontStyleSlant.Italic : SKFontStyleSlant.Upright) ?? SKTypeface.Default;
            SKTypeface t; if (reg.TryGetValue(name, out t)) return t;
            var w = st.HasFlag(FontStyle.Bold) ? SKFontStyleWeight.Bold : SKFontStyleWeight.Normal;
            var sl = st.HasFlag(FontStyle.Italic) ? SKFontStyleSlant.Italic : SKFontStyleSlant.Upright;
            return SKTypeface.FromFamilyName(name, w, SKFontStyleWidth.Normal, sl) ?? SKTypeface.Default;
        }
    }

    public sealed class Font : IDisposable
    {
        internal SKTypeface Face; internal float Px; public FontStyle Style; internal bool Pixelish; internal bool WantBold;
        string reqName;
        public Font(string name, float size) : this(name, size, FontStyle.Regular, GraphicsUnit.Point) { }
        public Font(string name, float size, FontStyle st) : this(name, size, st, GraphicsUnit.Point) { }
        public Font(string name, float size, FontStyle st, GraphicsUnit u)
        { reqName = name; Face = FontStore.Resolve(name, st); Px = System.Drawing.Px.Size(size, u); Style = st; Pixelish = u == GraphicsUnit.Pixel; WantBold = st.HasFlag(FontStyle.Bold); }
        public Font(FontFamily fam, float size) : this(fam, size, FontStyle.Regular, GraphicsUnit.Point) { }
        public Font(FontFamily fam, float size, FontStyle st) : this(fam, size, st, GraphicsUnit.Point) { }
        public Font(FontFamily fam, float size, FontStyle st, GraphicsUnit u)
        { reqName = fam.Name; Face = fam.Face ?? FontStore.Resolve(fam.Name, st); Px = System.Drawing.Px.Size(size, u); Style = st; Pixelish = u == GraphicsUnit.Pixel; WantBold = st.HasFlag(FontStyle.Bold); }
        public string Name { get { return Face != null ? Face.FamilyName : reqName; } }
        public float SizeInPoints { get { return Px * 72f / 96f; } }
        internal SKPaint NewPaint(SKColor col, bool antialias)
        {
            var p = new SKPaint { Typeface = Face ?? SKTypeface.Default, TextSize = Px, Color = col, IsAntialias = antialias && !Pixelish, SubpixelText = !Pixelish, LcdRenderText = false, IsLinearText = !Pixelish };
            if (WantBold && Face != null && !Face.IsBold) p.FakeBoldText = true;
            return p;
        }
        SKPaint _m;
        internal SKPaint Meas { get { if (_m == null) _m = NewPaint(SKColors.White, true); return _m; } }
        public float MeasureText(string s) { return Meas.MeasureText(s); }
        public float LineHeight { get { var m = Meas.FontMetrics; return (float)Math.Ceiling(m.Descent - m.Ascent + m.Leading); } }
        public float Ascent { get { return Meas.FontMetrics.Ascent; } }
        public int Height { get { return (int)LineHeight; } }
        public void Dispose() { if (_m != null) { _m.Dispose(); _m = null; } }
    }

    public sealed class StringFormat
    {
        public StringAlignment Alignment = StringAlignment.Near;
        public StringAlignment LineAlignment = StringAlignment.Near;
        public StringFormatFlags FormatFlags;
        public StringTrimming Trimming = StringTrimming.Character;
        public StringFormat() { }
        public StringFormat(StringFormatFlags f) { FormatFlags = f; }
        public static StringFormat GenericDefault { get { return new StringFormat(); } }
        public static StringFormat GenericTypographic { get { return new StringFormat(StringFormatFlags.NoClip) { Trimming = StringTrimming.None }; } }
    }

    public abstract class Brush : IDisposable { internal abstract SKShader Shader(SKRect bounds); internal virtual SKColor Solid { get { return SKColors.White; } } public virtual void Dispose() { } }

    public sealed class SolidBrush : Brush
    {
        public Color Color;
        public SolidBrush(Color c) { Color = c; }
        internal override SKColor Solid { get { return new SKColor(Color.R, Color.G, Color.B, Color.A); } }
        internal override SKShader Shader(SKRect b) { return null; }
    }

    public sealed class Pen : IDisposable
    {
        public Color Color; public float Width; public Drawing2D.DashStyle DashStyle = Drawing2D.DashStyle.Solid;
        public Pen(Color c) { Color = c; Width = 1; }
        public Pen(Color c, float w) { Color = c; Width = w; }
        public void Dispose() { }
        internal SKPaint Paint()
        {
            var p = new SKPaint { Color = new SKColor(Color.R, Color.G, Color.B, Color.A), IsStroke = true, StrokeWidth = Width <= 0 ? 1 : Width, IsAntialias = true, StrokeCap = SKStrokeCap.Butt };
            if (DashStyle == Drawing2D.DashStyle.Dash) p.PathEffect = SKPathEffect.CreateDash(new[] { Width * 3, Width * 3 }, 0);
            else if (DashStyle == Drawing2D.DashStyle.Dot) p.PathEffect = SKPathEffect.CreateDash(new[] { Width, Width * 2 }, 0);
            return p;
        }
    }

    namespace Drawing2D
    {
        public enum DashStyle { Solid, Dash, Dot, DashDot, DashDotDot, Custom }
        public enum SmoothingMode { Default, HighSpeed, HighQuality, None, AntiAlias }
        public enum InterpolationMode { Default, Low, High, Bilinear, Bicubic, NearestNeighbor, HighQualityBilinear, HighQualityBicubic }
        public enum PixelOffsetMode { Default, HighSpeed, HighQuality, None, Half }
        public enum CompositingQuality { Default, HighSpeed, HighQuality, GammaCorrected, AssumeLinear, Invalid }
        public enum WrapMode { Tile, TileFlipX, TileFlipY, TileFlipXY, Clamp }
        public enum LinearGradientMode { Horizontal, Vertical, ForwardDiagonal, BackwardDiagonal }

        public sealed class GraphicsPath : IDisposable
        {
            internal SKPath P = new SKPath();
            public void AddEllipse(RectangleF r) { P.AddOval(new SKRect(r.X, r.Y, r.Right, r.Bottom)); }
            public void Dispose() { P.Dispose(); }
        }

        public sealed class LinearGradientBrush : Brush
        {
            RectangleF rect; Color c1, c2; float angle; bool vertical; float blendPeak = -1;
            public LinearGradientBrush(RectangleF r, Color a, Color b, float ang) { rect = r; c1 = a; c2 = b; angle = ang; }
            public LinearGradientBrush(RectangleF r, Color a, Color b, LinearGradientMode m) { rect = r; c1 = a; c2 = b; vertical = m == LinearGradientMode.Vertical; angle = vertical ? 90 : 0; }
            public void SetBlendTriangularShape(float focus) { blendPeak = focus; }
            static SKColor K(Color c) { return new SKColor(c.R, c.G, c.B, c.A); }
            internal override SKShader Shader(SKRect b)
            {
                SKPoint p0, p1;
                if (vertical || Math.Abs(angle - 90) < 1) { p0 = new SKPoint(rect.X, rect.Y); p1 = new SKPoint(rect.X, rect.Bottom); }
                else { p0 = new SKPoint(rect.X, rect.Y); p1 = new SKPoint(rect.Right, rect.Y); }
                if (blendPeak >= 0)
                    return SKShader.CreateLinearGradient(p0, p1, new[] { K(c1), K(c2), K(c1) }, new[] { 0f, blendPeak, 1f }, SKShaderTileMode.Clamp);
                return SKShader.CreateLinearGradient(p0, p1, new[] { K(c1), K(c2) }, null, SKShaderTileMode.Clamp);
            }
        }

        public sealed class PathGradientBrush : Brush
        {
            SKRect bounds; public Color CenterColor = Color.White; Color[] surround = { Color.Black }; PointF focus = new PointF(0, 0);
            public PathGradientBrush(GraphicsPath p) { bounds = p.P.Bounds; }
            public PointF FocusScales { set { focus = value; } }
            public Color[] SurroundColors { set { surround = value; } }
            static SKColor K(Color c) { return new SKColor(c.R, c.G, c.B, c.A); }
            internal override SKShader Shader(SKRect b)
            {
                var center = new SKPoint(bounds.MidX, bounds.MidY);
                float r = Math.Max(bounds.Width, bounds.Height) / 2f;
                var sc = surround.Length > 0 ? surround[0] : Color.Black;
                float start = Math.Max(0f, Math.Min(0.95f, Math.Max(focus.X, focus.Y)));
                return SKShader.CreateRadialGradient(center, r <= 0 ? 1 : r, new[] { K(CenterColor), K(sc) }, new[] { start, 1f }, SKShaderTileMode.Clamp);
            }
        }
    }

    namespace Imaging
    {
        public enum PixelFormat { Format32bppArgb = 2498570, Format24bppRgb = 137224, DontCare = 0 }
        public sealed class ColorMatrix { public float Matrix33 = 1f; public ColorMatrix() { } }
        public sealed class ImageAttributes : IDisposable { internal float Alpha = 1f; public void SetColorMatrix(ColorMatrix m) { Alpha = m.Matrix33; } public void Dispose() { } }
    }

    namespace Text
    {
        public enum TextRenderingHint { SystemDefault, SingleBitPerPixelGridFit, SingleBitPerPixel, AntiAliasGridFit, AntiAlias, ClearTypeGridFit }
        public abstract class FontCollection { internal readonly List<FontFamily> fams = new List<FontFamily>(); public FontFamily[] Families { get { return fams.ToArray(); } } }
        public sealed class PrivateFontCollection : FontCollection
        {
            public void AddFontFile(string path)
            {
                var t = SKTypeface.FromFile(path);
                if (t != null) { FontStore.Register(t); fams.Add(new FontFamily(t, t.FamilyName)); }
            }
        }
    }

    public class Image : IDisposable
    {
        internal SKBitmap Bmp;
        public int Width { get { return Bmp.Width; } }
        public int Height { get { return Bmp.Height; } }
        public Size Size { get { return new Size(Bmp.Width, Bmp.Height); } }
        public Imaging.PixelFormat PixelFormat { get { return Imaging.PixelFormat.Format32bppArgb; } }
        public virtual void Dispose() { if (Bmp != null) { Bmp.Dispose(); Bmp = null; } }
    }

    public sealed class Bitmap : Image
    {
        public Bitmap(int w, int h) { Bmp = new SKBitmap(Math.Max(1, w), Math.Max(1, h), SKColorType.Bgra8888, SKAlphaType.Premul); }
        public Bitmap(int w, int h, Imaging.PixelFormat fmt) : this(w, h) { }
        internal Bitmap(SKBitmap b) { Bmp = b; }
        public void SetPixel(int x, int y, Color c) { Bmp.SetPixel(x, y, new SKColor(c.R, c.G, c.B, c.A)); }
        public Bitmap Clone(Rectangle r, Imaging.PixelFormat fmt)
        {
            var dst = new SKBitmap(r.Width, r.Height, SKColorType.Bgra8888, SKAlphaType.Premul);
            using (var cv = new SKCanvas(dst)) cv.DrawBitmap(Bmp, new SKRect(r.X, r.Y, r.Right, r.Bottom), new SKRect(0, 0, r.Width, r.Height));
            return new Bitmap(dst);
        }
        public IntPtr GetHicon() { return IconStore.Register(Bmp); }
    }

    static class IconStore
    {
        static int seq = 1; static readonly Dictionary<IntPtr, SKBitmap> map = new Dictionary<IntPtr, SKBitmap>();
        public static IntPtr Register(SKBitmap b) { var h = new IntPtr(seq++); map[h] = b.Copy(); return h; }
        public static SKBitmap Get(IntPtr h) { SKBitmap b; return map.TryGetValue(h, out b) ? b : null; }
    }

    public sealed class Icon : IDisposable
    {
        internal SKBitmap Bmp;
        internal Icon(SKBitmap b) { Bmp = b; }
        public Icon(Icon src, int w, int h) { Bmp = src.Bmp != null ? src.Bmp.Resize(new SKImageInfo(w, h), SKFilterQuality.High) : null; }
        public static Icon FromHandle(IntPtr h) { return new Icon(IconStore.Get(h)); }
        public static Icon ExtractAssociatedIcon(string path) { return new Icon((SKBitmap)null); }
        public void Dispose() { if (Bmp != null) { Bmp.Dispose(); Bmp = null; } }
    }

    public static class SystemIcons { public static Icon Application { get { return new Icon((SKBitmap)null); } } }

    public sealed class Region : IDisposable { internal Rectangle R; public Region(Rectangle r) { R = r; } public void Dispose() { } }

    public sealed class GraphicsState { internal int Count; }

    public sealed class Graphics : IDisposable
    {
        internal SKCanvas C; bool own; SKBitmap target;
        public Drawing2D.SmoothingMode SmoothingMode = Drawing2D.SmoothingMode.AntiAlias;
        public Drawing2D.InterpolationMode InterpolationMode = Drawing2D.InterpolationMode.Bilinear;
        public Drawing2D.PixelOffsetMode PixelOffsetMode = Drawing2D.PixelOffsetMode.Default;
        public Drawing2D.CompositingQuality CompositingQuality = Drawing2D.CompositingQuality.Default;
        public Text.TextRenderingHint TextRenderingHint = Text.TextRenderingHint.AntiAliasGridFit;

        internal Graphics(SKCanvas c) { C = c; }
        public static Graphics FromImage(Image img) { var cv = new SKCanvas(img.Bmp); var g = new Graphics(cv) { own = true, target = img.Bmp }; return g; }
        public void Dispose() { if (own && C != null) { C.Dispose(); C = null; } }

        bool AA { get { return SmoothingMode != Drawing2D.SmoothingMode.None && SmoothingMode != Drawing2D.SmoothingMode.HighSpeed; } }
        SKFilterQuality FQ { get { return InterpolationMode == Drawing2D.InterpolationMode.NearestNeighbor ? SKFilterQuality.None : SKFilterQuality.Medium; } }

        public GraphicsState Save() { int n = C.Save(); return new GraphicsState { Count = n }; }
        public void Restore(GraphicsState s) { if (s != null) C.RestoreToCount(s.Count); }
        public void SetClip(RectangleF r) { C.ClipRect(new SKRect(r.X, r.Y, r.Right, r.Bottom), SKClipOperation.Intersect, false); }
        public void TranslateTransform(float dx, float dy) { C.Translate(dx, dy); }

        public void Clear(Color c) { C.Clear(new SKColor(c.R, c.G, c.B, c.A)); }

        SKPaint Fill(Brush b, SKRect bounds)
        {
            var p = new SKPaint { IsAntialias = AA };
            var sh = b.Shader(bounds);
            if (sh != null) p.Shader = sh; else p.Color = b.Solid;
            return p;
        }

        public void FillRectangle(Brush b, float x, float y, float w, float h) { var r = new SKRect(x, y, x + w, y + h); using (var p = Fill(b, r)) C.DrawRect(r, p); }
        public void FillRectangle(Brush b, int x, int y, int w, int h) { FillRectangle(b, (float)x, y, w, h); }
        public void FillRectangle(Brush b, Rectangle r) { FillRectangle(b, (float)r.X, r.Y, r.Width, r.Height); }
        public void FillRectangle(Brush b, RectangleF r) { FillRectangle(b, r.X, r.Y, r.Width, r.Height); }

        public void FillEllipse(Brush b, float x, float y, float w, float h) { var r = new SKRect(x, y, x + w, y + h); using (var p = Fill(b, r)) C.DrawOval(r, p); }
        public void FillEllipse(Brush b, int x, int y, int w, int h) { FillEllipse(b, (float)x, y, w, h); }
        public void FillEllipse(Brush b, RectangleF r) { FillEllipse(b, r.X, r.Y, r.Width, r.Height); }

        public void FillPolygon(Brush b, PointF[] pts)
        {
            using (var path = new SKPath())
            {
                path.MoveTo(pts[0].X, pts[0].Y); for (int i = 1; i < pts.Length; i++) path.LineTo(pts[i].X, pts[i].Y); path.Close();
                using (var p = Fill(b, path.Bounds)) C.DrawPath(path, p);
            }
        }

        public void DrawRectangle(Pen pen, float x, float y, float w, float h) { using (var p = pen.Paint()) C.DrawRect(new SKRect(x, y, x + w, y + h), p); }
        public void DrawRectangle(Pen pen, int x, int y, int w, int h) { DrawRectangle(pen, (float)x, y, w, h); }
        public void DrawEllipse(Pen pen, float x, float y, float w, float h) { using (var p = pen.Paint()) C.DrawOval(new SKRect(x, y, x + w, y + h), p); }
        public void DrawEllipse(Pen pen, int x, int y, int w, int h) { DrawEllipse(pen, (float)x, y, w, h); }
        public void DrawArc(Pen pen, float x, float y, float w, float h, float start, float sweep) { using (var p = pen.Paint()) using (var path = new SKPath()) { path.AddArc(new SKRect(x, y, x + w, y + h), start, sweep); C.DrawPath(path, p); } }
        public void DrawLine(Pen pen, float x1, float y1, float x2, float y2) { using (var p = pen.Paint()) C.DrawLine(x1, y1, x2, y2, p); }
        public void DrawLine(Pen pen, int x1, int y1, int x2, int y2) { DrawLine(pen, (float)x1, y1, x2, y2); }
        public void DrawLine(Pen pen, PointF a, PointF b) { DrawLine(pen, a.X, a.Y, b.X, b.Y); }
        public void DrawLines(Pen pen, PointF[] pts) { using (var p = pen.Paint()) for (int i = 1; i < pts.Length; i++) C.DrawLine(pts[i - 1].X, pts[i - 1].Y, pts[i].X, pts[i].Y, p); }
        public void DrawPolygon(Pen pen, PointF[] pts) { using (var p = pen.Paint()) using (var path = new SKPath()) { path.MoveTo(pts[0].X, pts[0].Y); for (int i = 1; i < pts.Length; i++) path.LineTo(pts[i].X, pts[i].Y); path.Close(); C.DrawPath(path, p); } }

        public void DrawImageUnscaled(Image img, int x, int y) { C.DrawBitmap(img.Bmp, x, y); }
        public void DrawImage(Image img, Rectangle dst, Rectangle src, GraphicsUnit u) { C.DrawBitmap(img.Bmp, new SKRect(src.X, src.Y, src.Right, src.Bottom), new SKRect(dst.X, dst.Y, dst.Right, dst.Bottom)); }
        public void DrawImage(Image img, RectangleF dst, RectangleF src, GraphicsUnit u) { C.DrawBitmap(img.Bmp, new SKRect(src.X, src.Y, src.Right, src.Bottom), new SKRect(dst.X, dst.Y, dst.Right, dst.Bottom)); }
        public void DrawImage(Image img, Rectangle dst, int sx, int sy, int sw, int sh, GraphicsUnit u, Imaging.ImageAttributes attr)
        {
            using (var p = new SKPaint { IsAntialias = AA, FilterQuality = FQ })
            {
                if (attr != null && attr.Alpha < 1f) p.Color = new SKColor(255, 255, 255, (byte)(Math.Max(0, Math.Min(1, attr.Alpha)) * 255));
                C.DrawBitmap(img.Bmp, new SKRect(sx, sy, sx + sw, sy + sh), new SKRect(dst.X, dst.Y, dst.Right, dst.Bottom), p);
            }
        }
        public void DrawIcon(Icon icon, Rectangle r) { if (icon != null && icon.Bmp != null) C.DrawBitmap(icon.Bmp, new SKRect(r.X, r.Y, r.Right, r.Bottom)); }



        public SizeF MeasureString(string s, Font f) { return MeasureCore(s, f, int.MaxValue); }
        public SizeF MeasureString(string s, Font f, int width) { return MeasureCore(s, f, width <= 0 ? int.MaxValue : width); }

        SizeF MeasureCore(string s, Font f, int width)
        {
            if (string.IsNullOrEmpty(s)) return new SizeF(0, f.LineHeight);
            var lines = WrapLines(s, f, width);
            float w = 0; foreach (var ln in lines) w = Math.Max(w, f.MeasureText(ln));
            return new SizeF(w, f.LineHeight * lines.Count);
        }

        List<string> WrapLines(string s, Font f, int width)
        {
            var outp = new List<string>();
            foreach (var raw in s.Replace("\r", "").Split('\n'))
            {
                if (width == int.MaxValue) { outp.Add(raw); continue; }
                if (f.MeasureText(raw) <= width || raw.Length == 0) { outp.Add(raw); continue; }
                var words = raw.Split(' '); var cur = "";
                foreach (var wd in words)
                {
                    var trial = cur.Length == 0 ? wd : cur + " " + wd;
                    if (f.MeasureText(trial) <= width || cur.Length == 0) cur = trial;
                    else { outp.Add(cur); cur = wd; }
                    while (f.MeasureText(cur) > width && cur.Length > 1)
                    {
                        int cut = cur.Length; while (cut > 1 && f.MeasureText(cur.Substring(0, cut)) > width) cut--;
                        outp.Add(cur.Substring(0, cut)); cur = cur.Substring(cut);
                    }
                }
                outp.Add(cur);
            }
            return outp;
        }

        public void DrawString(string s, Font f, Brush b, float x, float y) { DrawString(s, f, b, new RectangleF(x, y, 100000, 100000), StringFormat.GenericDefault); }
        public void DrawString(string s, Font f, Brush b, RectangleF r) { DrawString(s, f, b, r, StringFormat.GenericDefault); }
        public void DrawString(string s, Font f, Brush b, RectangleF r, StringFormat fmt)
        {
            if (string.IsNullOrEmpty(s)) return;
            fmt = fmt ?? StringFormat.GenericDefault;
            bool nowrap = (fmt.FormatFlags & StringFormatFlags.NoWrap) != 0;
            var col = b is SolidBrush ? ((SolidBrush)b).Color : Color.White;
            float lh = f.LineHeight;
            var lines = WrapLines(s, f, nowrap ? int.MaxValue : (int)Math.Floor(r.Width));
            if (fmt.Trimming != StringTrimming.None && nowrap)
                for (int i = 0; i < lines.Count; i++) lines[i] = Ellipsize(lines[i], f, r.Width, fmt.Trimming);
            float totalH = lh * lines.Count;
            float startY = r.Y - f.Ascent;
            if (fmt.LineAlignment == StringAlignment.Center) startY += (r.Height - totalH) / 2f;
            else if (fmt.LineAlignment == StringAlignment.Far) startY += r.Height - totalH;
            bool clip = (fmt.FormatFlags & StringFormatFlags.NoClip) == 0 && r.Width < 90000;
            var st = clip ? Save() : null;
            if (clip) C.ClipRect(new SKRect(r.X, r.Y, r.Right, r.Bottom), SKClipOperation.Intersect, false);
            using (var p = f.NewPaint(new SKColor(col.R, col.G, col.B, col.A), TextRenderingHint != Text.TextRenderingHint.SingleBitPerPixelGridFit))
            {
                float yy = startY;
                foreach (var ln in lines)
                {
                    float w = p.MeasureText(ln); float xx = r.X;
                    if (fmt.Alignment == StringAlignment.Center) xx = r.X + (r.Width - w) / 2f;
                    else if (fmt.Alignment == StringAlignment.Far) xx = r.Right - w;
                    C.DrawText(ln, xx, yy, p);
                    yy += lh;
                }
            }
            if (clip) Restore(st);
        }

        string Ellipsize(string s, Font f, float width, StringTrimming t)
        {
            if (f.MeasureText(s) <= width) return s;
            string ell = (t == StringTrimming.EllipsisCharacter || t == StringTrimming.EllipsisWord) ? "…" : "";
            int n = s.Length;
            while (n > 0 && f.MeasureText(s.Substring(0, n) + ell) > width) n--;
            return s.Substring(0, n) + ell;
        }
    }

    public sealed class TextureBrush : Brush
    {
        Image img; Drawing2D.WrapMode mode; float tx, ty;
        public TextureBrush(Image i, Drawing2D.WrapMode m) { img = i; mode = m; }
        public void ResetTransform() { tx = ty = 0; }
        public void TranslateTransform(float dx, float dy) { tx += dx; ty += dy; }
        internal override SKShader Shader(SKRect b)
        {
            var tm = mode == Drawing2D.WrapMode.Clamp ? SKShaderTileMode.Clamp : SKShaderTileMode.Repeat;
            var mat = SKMatrix.CreateTranslation(tx, ty);
            using (var im = SKImage.FromBitmap(img.Bmp))
                return SKShader.CreateImage(im, tm, tm, mat);
        }
    }
}
