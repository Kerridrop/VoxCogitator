using System;
using System.Collections.Generic;
using System.Linq;
using System.Drawing;
using SkiaSharp;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media;
using Avalonia.Threading;
using Avalonia.Input;
using Avalonia.Rendering.SceneGraph;
using Avalonia.Skia;
using AV = Avalonia;

namespace System.Windows.Forms
{
    public class Form : ContainerControl
    {
        internal int WinLeft, WinTop;
        public bool TopMost { get; set; }
        public bool ShowInTaskbar { get; set; } = true;
        public bool KeyPreview { get; set; }
        public double Opacity { get; set; } = 1.0;
        public FormBorderStyle FormBorderStyle { get; set; } = FormBorderStyle.Sizable;
        public FormStartPosition StartPosition { get; set; } = FormStartPosition.WindowsDefaultLocation;
        public FormWindowState WindowState { get; set; } = FormWindowState.Normal;
        public Icon Icon { get; set; }
        public event FormClosedEventHandler FormClosed;
        internal CogWindow Win;
        static Form active;
        public static Form ActiveForm { get { return active; } }

        public Form() { BackColor = System.Drawing.Color.FromArgb(4, 9, 5); }

        protected virtual void OnFormClosing(FormClosingEventArgs e) { }
        protected virtual void OnFormClosed(FormClosedEventArgs e) { }
        protected virtual void OnDeactivate(EventArgs e) { }
        protected virtual void SetVisibleCore(bool visible) { }
        protected virtual bool ShowWithoutActivation { get { return false; } }

        public void Activate() { active = this; if (Win != null) Win.Activate(); }
        public void Close()
        {
            var e = new FormClosingEventArgs { CloseReason = CloseReason.UserClosing };
            OnFormClosing(e);
            if (e.Cancel) return;
            if (Win != null) Win.CloseReal();
            OnFormClosed(new FormClosedEventArgs());
            if (FormClosed != null) FormClosed(this, new FormClosedEventArgs());
        }

        internal void EnsureWindow() { if (Win == null) { Win = new CogWindow(this); active = this; } }
        internal void Reposition()
        {
            if (Win == null) return;
            if (StartPosition == FormStartPosition.CenterScreen)
            { var wa = Host.PrimaryWorkArea(); WinLeft = wa.X + (wa.Width - Width) / 2; WinTop = wa.Y + (wa.Height - Height) / 2; }
            Win.ApplyBounds();
        }
        internal void OnWindowResized(int w, int h) { SetBounds(0, 0, w, h); Invalidate(); }
        internal void PaintForm(Graphics g) { PaintTree(g); }
    }

    static class Host
    {
        static Form pending;
        internal static readonly List<IMessageFilter> Filters = new List<IMessageFilter>();
        internal static Control Focus;
        internal static MouseButtons Buttons;
        static readonly List<Timer> timers = new List<Timer>();
        static Point pointerScreen;
        public static bool OnUi { get { return Dispatcher.UIThread.CheckAccess(); } }

        public static void Run(Form f)
        {
            pending = f;
            Boot.Start();
        }
        internal static void BootForm() { if (pending == null) return; pending.EnsureWindow(); pending.Reposition(); pending.Win.Show(); }

        public static void Dirty(Control c) { var f = c != null ? c.FindForm() : null; if (f != null && f.Win != null) f.Win.Invalidate(); }
        public static void FlushPaint() { }
        public static void RenderOnce(Form f, string path)
        {
            int w = f.Width > 0 ? f.Width : 1280, h = f.Height > 0 ? f.Height : 860;
            f.OnWindowResized(w, h); f.PerformLayout();
            using (var bmp = new SKBitmap(w, h, SKColorType.Bgra8888, SKAlphaType.Premul))
            using (var cv = new SKCanvas(bmp))
            {
                var g = new Graphics(cv); f.PaintForm(g);
                using (var im = SKImage.FromBitmap(bmp)) using (var d = im.Encode(SKEncodedImageFormat.Png, 90)) using (var fs = System.IO.File.OpenWrite(path)) d.SaveTo(fs);
            }
            Console.Error.WriteLine("[RENDER] " + path);
        }
        public static Graphics OffscreenGraphics(Control c) { var bmp = new Bitmap(Math.Max(1, c.Width), Math.Max(1, c.Height)); return Graphics.FromImage(bmp); }

        static readonly List<Timer> pendingTimers = new List<Timer>();
        static bool booted;
        public static void AddTimer(Timer t)
        {
            if (!timers.Contains(t)) timers.Add(t);
            if (!booted) { if (!pendingTimers.Contains(t)) pendingTimers.Add(t); return; }
            StartNative(t);
        }
        static void StartNative(Timer t)
        {
            var dt = t.Native as DispatcherTimer;
            if (dt == null) { dt = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(t.Ms) }; dt.Tick += (s, e) => t.Fire(); t.Native = dt; }
            dt.Interval = TimeSpan.FromMilliseconds(t.Ms); dt.Start();
        }
        internal static void FlushTimers() { booted = true; foreach (var t in pendingTimers.ToArray()) StartNative(t); pendingTimers.Clear(); }
        public static void RemoveTimer(Timer t) { var dt = t.Native as DispatcherTimer; if (dt != null) dt.Stop(); timers.Remove(t); }
        public static void Retime(Timer t) { var dt = t.Native as DispatcherTimer; if (dt != null) dt.Interval = TimeSpan.FromMilliseconds(t.Ms); }

        public static Rectangle PrimaryWorkArea()
        {
            try { if (pending != null && pending.Win != null) { var r = pending.Win.AvScreen(); if (r != null) return r.Value; } } catch { }
            return new Rectangle(0, 0, 1600, 1000);
        }
        public static Point PointerScreen() { return pointerScreen; }
        internal static void SetPointerScreen(Point p) { pointerScreen = p; }
        public static void ShowMenu(ToolStripDropDown menu, Control owner, Point screen) { }
        public static void Notify(string title, string text) { Console.Error.WriteLine("[NOTIFY] " + title + ": " + text); }
        public static IAsyncResult Post(Delegate d) { Dispatcher.UIThread.Post(() => { try { d.DynamicInvoke(); } catch { } }); return new DummyAsync(); }
        public static object InvokeSync(Delegate d) { if (Dispatcher.UIThread.CheckAccess()) return d.DynamicInvoke(); object r = null; Dispatcher.UIThread.InvokeAsync(() => { r = d.DynamicInvoke(); }).Wait(); return r; }
    }

    internal class DummyAsync : IAsyncResult { public object AsyncState { get { return null; } } public System.Threading.WaitHandle AsyncWaitHandle { get { return null; } } public bool CompletedSynchronously { get { return false; } } public bool IsCompleted { get { return true; } } }

    public class ShimApp : AV.Application
    {
        public override void Initialize() { }
        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime d) d.ShutdownMode = ShutdownMode.OnMainWindowClose;
            Host.FlushTimers(); Host.BootForm();
            base.OnFrameworkInitializationCompleted();
        }
    }

    internal class CogWindow
    {
        readonly Form form; internal readonly Window W; readonly CogHost host;
        public CogWindow(Form f)
        {
            form = f; host = new CogHost(f);
            W = new Window
            {
                SystemDecorations = f.FormBorderStyle == FormBorderStyle.None ? SystemDecorations.None : SystemDecorations.Full,
                Topmost = f.TopMost, ShowInTaskbar = f.ShowInTaskbar, Opacity = f.Opacity,
                CanResize = f.FormBorderStyle != FormBorderStyle.None,
                Width = f.Width > 0 ? f.Width : 1280, Height = f.Height > 0 ? f.Height : 860,
                Background = Brushes.Black, Content = host, Title = "Cogitator"
            };
            if (f.StartPosition == FormStartPosition.CenterScreen) W.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }
        public void Show() { if (form.StartPosition == FormStartPosition.Manual) ApplyBounds(); W.Show(); }
        public void Activate() { W.Activate(); }
        public void Invalidate() { Dispatcher.UIThread.Post(() => host.InvalidateVisual()); }
        public void CloseReal() { W.Close(); }
        public void ApplyBounds() { if (form.StartPosition == FormStartPosition.Manual) W.Position = new AV.PixelPoint(form.WinLeft, form.WinTop); if (form.Width > 0) { W.Width = form.Width; W.Height = form.Height; } }
        public Rectangle? AvScreen() { try { var sc = W.Screens.ScreenFromWindow(W) ?? W.Screens.Primary; if (sc != null) { var wk = sc.WorkingArea; return new Rectangle(wk.X, wk.Y, wk.Width, wk.Height); } } catch { } return null; }
    }

    internal class CogHost : global::Avalonia.Controls.Control
    {
        readonly Form form; Control hover;
        public CogHost(Form f) { form = f; Focusable = true; }

        protected override AV.Size ArrangeOverride(AV.Size finalSize)
        {
            form.OnWindowResized((int)Math.Round(finalSize.Width), (int)Math.Round(finalSize.Height));
            return base.ArrangeOverride(finalSize);
        }

        public override void Render(DrawingContext ctx)
        {
            ctx.Custom(new CogDraw(new AV.Rect(Bounds.Size), form, VisualRoot != null ? VisualRoot.RenderScaling : 1.0));
        }

        Point Loc(PointerEventArgs e) { var p = e.GetPosition(this); return new Point((int)Math.Round(p.X), (int)Math.Round(p.Y)); }

        protected override void OnPointerMoved(PointerEventArgs e)
        {
            var p = Loc(e); Host.SetPointerScreen(new Point(form.WinLeft + p.X, form.WinTop + p.Y));
            if (Filter(0x200)) return;
            int lx, ly; var c = form.HitTest(p.X, p.Y, out lx, out ly);
            if (c != hover) { if (hover != null) hover.RaiseMouseLeave(); hover = c; if (c != null) c.RaiseMouseEnter(); }
            if (c != null) c.RaiseMouseMove(new MouseEventArgs(Host.Buttons, 0, lx, ly, 0));
        }
        protected override void OnPointerPressed(PointerPressedEventArgs e)
        {
            var pr = e.GetCurrentPoint(this).Properties;
            Host.Buttons = pr.IsLeftButtonPressed ? MouseButtons.Left : pr.IsRightButtonPressed ? MouseButtons.Right : MouseButtons.None;
            if (Filter(0x201)) return;
            var p = Loc(e); int lx, ly; var c = form.HitTest(p.X, p.Y, out lx, out ly);
            if (c != null) { Host.Focus = c; c.RaiseMouseDown(new MouseEventArgs(Host.Buttons, 1, lx, ly, 0)); }
        }
        protected override void OnPointerReleased(PointerReleasedEventArgs e)
        {
            var p = Loc(e); int lx, ly; var c = form.HitTest(p.X, p.Y, out lx, out ly);
            var btn = Host.Buttons; Host.Buttons = MouseButtons.None;
            if (c != null) { c.RaiseMouseUp(new MouseEventArgs(btn, 1, lx, ly, 0)); c.RaiseMouseClick(new MouseEventArgs(btn, 1, lx, ly, 0)); }
        }
        protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
        {
            if (Filter(0x20A)) return;
            var p = Loc(e); int lx, ly; var c = form.HitTest(p.X, p.Y, out lx, out ly);
            if (c != null) c.RaiseMouseWheel(new MouseEventArgs(Host.Buttons, 0, lx, ly, (int)(e.Delta.Y * 120)));
        }
        protected override void OnKeyDown(global::Avalonia.Input.KeyEventArgs e)
        {
            if (Filter(0x100)) { e.Handled = true; return; }
            var kea = new System.Windows.Forms.KeyEventArgs(MapKey(e.Key), e.KeyModifiers.HasFlag(KeyModifiers.Control));
            (Host.Focus ?? form).RaiseKeyDown(kea);
            if (kea.Handled) e.Handled = true;
        }
        static Keys MapKey(Key k)
        {
            switch (k)
            {
                case Key.Escape: return Keys.Escape; case Key.Enter: return Keys.Enter;
                case Key.Left: return Keys.Left; case Key.Right: return Keys.Right; case Key.Up: return Keys.Up; case Key.Down: return Keys.Down;
                case Key.A: return Keys.A;
            }
            if (k >= Key.D1 && k <= Key.D5) return Keys.D1 + (k - Key.D1);
            if (k >= Key.NumPad1 && k <= Key.NumPad5) return Keys.NumPad1 + (k - Key.NumPad1);
            return Keys.None;
        }
        bool Filter(int msg)
        {
            if (Host.Filters.Count == 0) return false;
            var m = new Message { Msg = msg };
            foreach (var f in Host.Filters.ToArray()) if (f.PreFilterMessage(ref m)) return true;
            return false;
        }
    }

    internal class CogDraw : ICustomDrawOperation
    {
        readonly AV.Rect bounds; readonly Form form; readonly double scale;
        public CogDraw(AV.Rect b, Form f, double s) { bounds = b; form = f; scale = s; }
        public AV.Rect Bounds { get { return bounds; } }
        public bool HitTest(AV.Point p) { return false; }
        public bool Equals(ICustomDrawOperation other) { return false; }
        public void Dispose() { }
        public void Render(ImmediateDrawingContext context)
        {
            var feat = context.TryGetFeature(typeof(ISkiaSharpApiLeaseFeature)) as ISkiaSharpApiLeaseFeature;
            if (feat == null) return;
            using (var lease = feat.Lease())
            {
                var canvas = lease.SkCanvas;
                int save = canvas.Save();
                try { var g = new Graphics(canvas); form.PaintForm(g); }
                finally { canvas.RestoreToCount(save); }
            }
        }
    }
}
