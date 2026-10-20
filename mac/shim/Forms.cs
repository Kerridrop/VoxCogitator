using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Drawing;
using SkiaSharp;

namespace System.Windows.Forms
{
    public enum DockStyle { None, Top, Bottom, Left, Right, Fill }
    [Flags] public enum AnchorStyles { None = 0, Top = 1, Bottom = 2, Left = 4, Right = 8 }
    public enum FlowDirection { LeftToRight, TopDown, RightToLeft, BottomUp }
    public enum SizeType { AutoSize, Absolute, Percent }
    public enum BorderStyle { None, FixedSingle, Fixed3D }
    public enum DrawMode { Normal, OwnerDrawFixed, OwnerDrawVariable }
    public enum FormBorderStyle { None, FixedSingle, Fixed3D, FixedDialog, Sizable, FixedToolWindow, SizableToolWindow }
    public enum FormStartPosition { Manual, CenterScreen, CenterParent, WindowsDefaultLocation }
    public enum FormWindowState { Normal, Minimized, Maximized }
    public enum AutoScaleMode { None, Font, Dpi, Inherit }
    public enum DialogResult { None, OK, Cancel, Yes, No, Abort, Retry, Ignore }
    public enum MessageBoxButtons { OK, OKCancel, YesNo, YesNoCancel }
    public enum MessageBoxIcon { None, Error, Question, Warning, Information }
    public enum ToolTipIcon { None, Info, Warning, Error }
    public enum CloseReason { None, UserClosing, ApplicationExitCall, TaskManagerClosing, FormOwnerClosing, WindowsShutDown, MdiFormClosing }
    public enum RichTextBoxScrollBars { None, Horizontal, Vertical, Both, ForcedHorizontal, ForcedVertical, ForcedBoth }
    public enum UnhandledExceptionMode { Automatic, CatchException, ThrowException }
    public enum MouseButtons { None = 0, Left = 0x100000, Right = 0x200000, Middle = 0x400000 }
    [Flags] public enum ControlStyles { UserPaint = 2, AllPaintingInWmPaint = 0x2000, OptimizedDoubleBuffer = 0x20000, ResizeRedraw = 0x10, Selectable = 8 }

    public enum Keys
    {
        None = 0, Back = 8, Enter = 13, Escape = 27, Space = 32,
        Left = 37, Up = 38, Right = 39, Down = 40,
        A = 65, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
        D0 = 48, D1, D2, D3, D4, D5, D6, D7, D8, D9,
        NumPad0 = 96, NumPad1, NumPad2, NumPad3, NumPad4, NumPad5, NumPad6, NumPad7, NumPad8, NumPad9,
        Control = 0x20000, Shift = 0x10000, Alt = 0x40000
    }

    public struct Padding
    {
        public int Left, Top, Right, Bottom;
        public Padding(int all) { Left = Top = Right = Bottom = all; }
        public Padding(int l, int t, int r, int b) { Left = l; Top = t; Right = r; Bottom = b; }
        public int Horizontal { get { return Left + Right; } }
        public int Vertical { get { return Top + Bottom; } }
        public static readonly Padding Empty = new Padding(0);
    }

    public class EventArgs2 { }
    public class PaintEventArgs : EventArgs { public Graphics Graphics; internal PaintEventArgs(Graphics g) { Graphics = g; } }
    public class MouseEventArgs : EventArgs
    {
        public MouseButtons Button; public int X, Y, Delta;
        public MouseEventArgs(MouseButtons b, int clicks, int x, int y, int delta) { Button = b; X = x; Y = y; Delta = delta; }
        public Point Location { get { return new Point(X, Y); } }
    }
    public class KeyEventArgs : EventArgs
    {
        public Keys KeyCode; public bool Control; public bool Handled; public bool SuppressKeyPress;
        public KeyEventArgs(Keys k, bool ctrl) { KeyCode = k; Control = ctrl; }
    }
    public class LayoutEventArgs : EventArgs { }
    public class FormClosingEventArgs : EventArgs { public CloseReason CloseReason; public bool Cancel; }
    public class FormClosedEventArgs : EventArgs { public CloseReason CloseReason; }
    public delegate void FormClosingEventHandler(object s, FormClosingEventArgs e);
    public delegate void FormClosedEventHandler(object s, FormClosedEventArgs e);
    public class DrawItemEventArgs : EventArgs
    {
        public Graphics Graphics; public Font Font; public Rectangle Bounds; public int Index; public int State;
        public DrawItemEventArgs(Graphics g, Font f, Rectangle b, int i, int st) { Graphics = g; Font = f; Bounds = b; Index = i; State = st; }
    }
    public delegate void DrawItemEventHandler(object s, DrawItemEventArgs e);
    public static class DrawItemState { public const int None = 0; public const int Selected = 1; }

    public struct Message { public int Msg; public IntPtr WParam; public IntPtr LParam; }
    public interface IMessageFilter { bool PreFilterMessage(ref Message m); }
    public interface IWin32Window { IntPtr Handle { get; } }
    public class CreateParams { public int ExStyle; public int Style; }

    public sealed class Cursor { internal string Kind; internal Cursor(string k) { Kind = k; } public static Point Position { get { return Host.PointerScreen(); } } }
    public static class Cursors
    {
        public static readonly Cursor Default = new Cursor("default");
        public static readonly Cursor Hand = new Cursor("hand");
        public static readonly Cursor IBeam = new Cursor("ibeam");
    }

    public class Control : IWin32Window, IDisposable
    {
        internal Control parent;
        internal readonly ControlCollection controls;
        int x, y, w, h; bool visible = true, enabled = true;
        public Color BackColor = Color.FromArgb(4, 9, 5);
        public Color ForeColor = Color.FromArgb(176, 236, 186);
        public DockStyle Dock = DockStyle.None;
        public AnchorStyles Anchor = AnchorStyles.Top | AnchorStyles.Left;
        public Padding Margin = new Padding(3);
        public Padding Padding = new Padding(0);
        public Font Font = new Font("__mono__", 9f);
        public Cursor Cursor = Cursors.Default;
        public bool AutoSize;
        public Size MinimumSize;
        public object Tag;
        internal bool styleUserPaint;

        public event EventHandler Click, DoubleClick, GotFocus, LostFocus, HandleCreated, VisibleChanged, EnabledChanged;
        public event EventHandler SelectedIndexChanged;

        public Control() { controls = new ControlCollection(this); }

        public ControlCollection Controls { get { return controls; } }
        public Control Parent { get { return parent; } }
        public int Left { get { return x; } set { SetBounds(value, y, w, h); } }
        public int Top { get { return y; } set { SetBounds(x, value, w, h); } }
        public int Width { get { return w; } set { SetBounds(x, y, value, h); } }
        public int Height { get { return h; } set { SetBounds(x, y, w, value); } }
        public int Right { get { return x + w; } }
        public int Bottom { get { return y + h; } }
        public Point Location { get { return new Point(x, y); } set { SetBounds(value.X, value.Y, w, h); } }
        public Size Size { get { return new Size(w, h); } set { SetBounds(x, y, value.Width, value.Height); } }
        public Rectangle Bounds { get { return new Rectangle(x, y, w, h); } set { SetBounds(value.X, value.Y, value.Width, value.Height); } }
        public Rectangle ClientRectangle { get { return new Rectangle(0, 0, w, h); } }
        public Size ClientSize { get { return new Size(w, h); } set { SetBounds(x, y, value.Width, value.Height); } }

        public bool Visible { get { return visible && (parent == null || parent.Visible); } set { if (visible != value) { visible = value; OnVisibleChanged(EventArgs.Empty); if (VisibleChanged != null) VisibleChanged(this, EventArgs.Empty); Host.Dirty(this); } } }
        internal bool SelfVisible { get { return visible; } }
        public bool Enabled { get { return enabled; } set { if (enabled != value) { enabled = value; OnEnabledChanged(EventArgs.Empty); if (EnabledChanged != null) EnabledChanged(this, EventArgs.Empty); Invalidate(); } } }
        public bool Focused { get { return Host.Focus == this; } }
        public string Text { get; set; }
        public IntPtr Handle { get { return new IntPtr(GetHashCode()); } }
        public bool IsHandleCreated { get { return true; } }
        public bool IsDisposed { get; private set; }
        public bool InvokeRequired { get { return !Host.OnUi; } }
        public IAsyncResult BeginInvoke(Delegate d) { return Host.Post(d); }
        public object Invoke(Delegate d) { return Host.InvokeSync(d); }
        public static MouseButtons MouseButtons { get { return Host.Buttons; } }

        public void SetBounds(int nx, int ny, int nw, int nh)
        {
            bool resized = nw != w || nh != h;
            x = nx; y = ny; w = Math.Max(0, nw); h = Math.Max(0, nh);
            if (resized) { PerformLayout(); OnResize(EventArgs.Empty); }
            Host.Dirty(this);
        }

        public virtual void SetStyle(ControlStyles s, bool v) { if ((s & ControlStyles.UserPaint) != 0) styleUserPaint = v; }
        public bool DoubleBuffered { get; set; }

        public void SuspendLayout() { }
        public void ResumeLayout(bool b) { PerformLayout(); }
        bool laying;
        public void PerformLayout() { if (laying) return; laying = true; try { OnLayout(new LayoutEventArgs()); foreach (var c in controls.Items.ToArray()) c.PerformLayout(); } finally { laying = false; } }
        public void Invalidate() { Host.Dirty(this); }
        public void Invalidate(Rectangle r) { Host.Dirty(this); }
        public void Update() { Host.FlushPaint(); }
        public void BringToFront() { if (parent != null) { parent.controls.Items.Remove(this); parent.controls.Items.Add(this); parent.PerformLayout(); Host.Dirty(parent); } }
        public void Show() { Visible = true; }
        public void Hide() { Visible = false; }
        public bool Focus() { Host.Focus = this; return true; }
        public Form FindForm() { var c = this; while (c != null && !(c is Form)) c = c.parent; return c as Form; }
        public Graphics CreateGraphics() { return Host.OffscreenGraphics(this); }
        public void DrawToBitmap(Bitmap bmp, Rectangle r) { using (var g = Graphics.FromImage(bmp)) { g.TranslateTransform(-r.X, -r.Y); PaintTree(g); } }
        public Point PointToClient(Point screen) { var o = ScreenOrigin(); return new Point(screen.X - o.X, screen.Y - o.Y); }
        public Point PointToScreen(Point client) { var o = ScreenOrigin(); return new Point(client.X + o.X, client.Y + o.Y); }
        public Rectangle RectangleToScreen(Rectangle r) { var o = ScreenOrigin(); return new Rectangle(r.X + o.X, r.Y + o.Y, r.Width, r.Height); }

        internal Point ScreenOrigin()
        {
            int ox = 0, oy = 0; var c = this;
            while (c != null && !(c is Form)) { ox += c.x; oy += c.y; c = c.parent; }
            var f = c as Form; if (f != null) { ox += f.WinLeft; oy += f.WinTop; }
            return new Point(ox, oy);
        }

        protected virtual void OnPaint(PaintEventArgs e) { }
        protected virtual void OnResize(EventArgs e) { }
        protected virtual void OnLayout(LayoutEventArgs e) { LayoutChildren(); }
        protected virtual void OnVisibleChanged(EventArgs e) { }
        protected virtual void OnEnabledChanged(EventArgs e) { }
        protected virtual void OnHandleCreated(EventArgs e) { }
        protected virtual void OnMouseMove(MouseEventArgs e) { }
        protected virtual void OnMouseDown(MouseEventArgs e) { }
        protected virtual void OnMouseUp(MouseEventArgs e) { }
        protected virtual void OnMouseClick(MouseEventArgs e) { }
        protected virtual void OnMouseDoubleClick(MouseEventArgs e) { }
        protected virtual void OnMouseEnter(EventArgs e) { }
        protected virtual void OnMouseLeave(EventArgs e) { }
        protected virtual void OnMouseWheel(MouseEventArgs e) { }
        protected virtual void OnKeyDown(KeyEventArgs e) { }
        public bool Capture { get; set; }
        public Region Region { get; set; }
        public ContextMenuStrip ContextMenuStrip { get; set; }
        protected virtual void CreateHandle() { OnHandleCreated(EventArgs.Empty); }

        protected virtual CreateParams CreateParams { get { return new CreateParams(); } }
        protected virtual void WndProc(ref Message m) { }
        internal void PumpWndProc(ref Message m) { WndProc(ref m); }
        protected virtual void Dispose(bool disposing) { IsDisposed = true; }
        public void Dispose() { Dispose(true); }

        internal void RaiseMouseMove(MouseEventArgs e) { OnMouseMove(e); }
        internal void RaiseMouseDown(MouseEventArgs e) { OnMouseDown(e); }
        internal void RaiseMouseUp(MouseEventArgs e) { OnMouseUp(e); }
        internal void RaiseMouseClick(MouseEventArgs e) { OnMouseClick(e); if (Click != null) Click(this, EventArgs.Empty); }
        internal void RaiseMouseDouble(MouseEventArgs e) { OnMouseDoubleClick(e); if (DoubleClick != null) DoubleClick(this, EventArgs.Empty); }
        internal void RaiseMouseEnter() { OnMouseEnter(EventArgs.Empty); }
        internal void RaiseMouseLeave() { OnMouseLeave(EventArgs.Empty); }
        internal void RaiseMouseWheel(MouseEventArgs e) { OnMouseWheel(e); }
        internal void RaiseKeyDown(KeyEventArgs e) { OnKeyDown(e); }
        internal void RaiseSelectedIndexChanged() { if (SelectedIndexChanged != null) SelectedIndexChanged(this, EventArgs.Empty); }

        internal virtual void LayoutChildren() { Layout.Arrange(this); }

        internal void PaintTree(Graphics g)
        {
            if (!visible) return;
            var st = g.Save();
            g.SetClip(new RectangleF(0, 0, w, h));
            using (var b = new SolidBrush(BackColor)) g.FillRectangle(b, 0, 0, w, h);
            OnPaint(new PaintEventArgs(g));
            foreach (var c in controls.Items)
            {
                if (!c.SelfVisible) continue;
                var cs = g.Save();
                g.TranslateTransform(c.x, c.y);
                c.PaintTree(g);
                g.Restore(cs);
            }
            g.Restore(st);
        }

        internal Control HitTest(int px, int py, out int lx, out int ly)
        {
            lx = px; ly = py;
            if (!visible || px < 0 || py < 0 || px >= w || py >= h) return null;
            for (int i = controls.Items.Count - 1; i >= 0; i--)
            {
                var c = controls.Items[i];
                if (!c.SelfVisible) continue;
                int cl, ct;
                var hit = c.HitTest(px - c.x, py - c.y, out cl, out ct);
                if (hit != null) { lx = cl; ly = ct; return hit; }
            }
            return this;
        }

        public class ControlCollection : IEnumerable<Control>
        {
            readonly Control owner; internal readonly List<Control> Items = new List<Control>();
            public ControlCollection(Control o) { owner = o; }
            public void Add(Control c) { c.parent = owner; Items.Add(c); c.OnHandleCreated(EventArgs.Empty); if (c.HandleCreated != null) c.HandleCreated(c, EventArgs.Empty); owner.PerformLayout(); Host.Dirty(owner); }
            public void Remove(Control c) { Items.Remove(c); c.parent = null; owner.PerformLayout(); Host.Dirty(owner); }
            public int Count { get { return Items.Count; } }
            public IEnumerator<Control> GetEnumerator() { return Items.GetEnumerator(); }
            IEnumerator IEnumerable.GetEnumerator() { return Items.GetEnumerator(); }
        }
    }

    static class Layout
    {
        public static void Arrange(Control p)
        {
            int l = p.Padding.Left, t = p.Padding.Top, r = p.Width - p.Padding.Right, b = p.Height - p.Padding.Bottom;
            var ordered = Enumerable.Reverse(p.Controls.Items).ToList();
            foreach (var c in ordered)
            {
                switch (c.Dock)
                {
                    case DockStyle.Top: c.SetBounds(l, t, r - l, c.Height); t += c.Height; break;
                    case DockStyle.Bottom: c.SetBounds(l, b - c.Height, r - l, c.Height); b -= c.Height; break;
                    case DockStyle.Left: c.SetBounds(l, t, c.Width, b - t); l += c.Width; break;
                    case DockStyle.Right: c.SetBounds(r - c.Width, t, c.Width, b - t); r -= c.Width; break;
                }
            }
            foreach (var c in p.Controls.Items) if (c.Dock == DockStyle.Fill) c.SetBounds(l, t, r - l, b - t);
            foreach (var c in p.Controls.Items)
                if (c.Dock == DockStyle.None && (c.Anchor & (AnchorStyles.Right | AnchorStyles.Bottom)) != 0)
                {
                    int nx = c.Left, ny = c.Top, nw = c.Width, nh = c.Height;
                    if ((c.Anchor & AnchorStyles.Right) != 0 && (c.Anchor & AnchorStyles.Left) != 0) nw = r - c.Left;
                    if ((c.Anchor & AnchorStyles.Bottom) != 0 && (c.Anchor & AnchorStyles.Top) != 0) nh = b - c.Top;
                    c.SetBounds(nx, ny, nw, nh);
                }
        }
    }

    public class ScrollableControl : Control { protected virtual void OnMouseWheel2(MouseEventArgs e) { } }
    public class ContainerControl : ScrollableControl
    {
        public SizeF AutoScaleDimensions { get; set; }
        public AutoScaleMode AutoScaleMode { get; set; }
    }

    public class Panel : Control
    {
        public Panel() { BackColor = Color.FromArgb(4, 9, 5); }
        public BorderStyle BorderStyle { get; set; }
    }

    public class Label : Control
    {
        public new bool AutoSize { get; set; }
        public Label() { BackColor = Color.FromArgb(0, 0, 0, 0); }
        internal void Measure()
        {
            if (!AutoSize || string.IsNullOrEmpty(Text)) return;
            int hh = (int)Math.Ceiling(Font.LineHeight); int ww = (int)Math.Ceiling(Font.MeasureText(Text)) + 2;
            if (Width != ww || Height != hh) SetBounds(Left, Top, ww, Math.Max(hh, 12));
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Measure();
            if (string.IsNullOrEmpty(Text)) return;
            using (var b = new SolidBrush(ForeColor))
                e.Graphics.DrawString(Text, Font, b, new RectangleF(0, 0, Math.Max(Width, 4000), Height > 0 ? Height : Font.LineHeight),
                    new StringFormat(StringFormatFlags.NoWrap | StringFormatFlags.NoClip) { LineAlignment = StringAlignment.Center });
        }
    }

    public class FlowLayoutPanel : Panel
    {
        public FlowDirection FlowDirection = FlowDirection.LeftToRight;
        public bool WrapContents = true;
        internal override void LayoutChildren()
        {
            int cx = Padding.Left, cy = Padding.Top, rowMax = 0;
            foreach (var c in Controls.Items) { var lb = c as Label; if (lb != null) lb.Measure(); }
            foreach (var c in Controls.Items)
            {
                if (!c.SelfVisible) continue;
                if (FlowDirection == FlowDirection.TopDown)
                {
                    c.SetBounds(Padding.Left + c.Margin.Left, cy + c.Margin.Top, c.Dock == DockStyle.Fill || c.Width == 0 ? Width - Padding.Horizontal - c.Margin.Horizontal : c.Width, c.Height);
                    cy += c.Height + c.Margin.Vertical;
                }
                else
                {
                    c.SetBounds(cx + c.Margin.Left, cy + c.Margin.Top, c.Width, c.Height);
                    cx += c.Width + c.Margin.Horizontal; rowMax = Math.Max(rowMax, c.Height + c.Margin.Vertical);
                }
            }
        }
    }

    public class ColumnStyle { public SizeType SizeType; public float Width; public ColumnStyle(SizeType t, float w) { SizeType = t; Width = w; } }
    public class RowStyle { public SizeType SizeType; public float Height; public RowStyle(SizeType t, float h) { SizeType = t; Height = h; } }
    public class TableLayoutColumnStyleCollection { internal readonly List<ColumnStyle> L = new List<ColumnStyle>(); public int Add(ColumnStyle s) { L.Add(s); return L.Count - 1; } }
    public class TableLayoutRowStyleCollection { internal readonly List<RowStyle> L = new List<RowStyle>(); public int Add(RowStyle s) { L.Add(s); return L.Count - 1; } }
    public class TableLayoutControlCollection
    {
        readonly TableLayoutPanel p;
        internal TableLayoutControlCollection(TableLayoutPanel panel) { p = panel; }
        public void Add(Control c) { ((Control)p).Controls.Add(c); }
        public void Add(Control c, int col, int row) { p.AddCell(c, col, row); }
    }

    public class TableLayoutPanel : Panel
    {
        public int ColumnCount, RowCount;
        readonly TableLayoutColumnStyleCollection cols = new TableLayoutColumnStyleCollection();
        readonly TableLayoutRowStyleCollection rows = new TableLayoutRowStyleCollection();
        readonly Dictionary<Control, int[]> cell = new Dictionary<Control, int[]>();
        readonly Dictionary<Control, int> span = new Dictionary<Control, int>();
        TableLayoutControlCollection tcoll;
        public TableLayoutColumnStyleCollection ColumnStyles { get { return cols; } }
        public TableLayoutRowStyleCollection RowStyles { get { return rows; } }
        public new TableLayoutControlCollection Controls { get { if (tcoll == null) tcoll = new TableLayoutControlCollection(this); return tcoll; } }
        internal void AddCell(Control c, int col, int row) { base.Controls.Add(c); cell[c] = new[] { col, row }; }
        public void SetColumnSpan(Control c, int s) { span[c] = s; }
        internal override void LayoutChildren()
        {
            if (ColumnCount <= 0 || RowCount <= 0) return;
            var items = base.Controls.Items;
            float totW = Width, totH = Height;
            var cw = new float[ColumnCount]; var rh = new float[RowCount];
            for (int i = 0; i < ColumnCount; i++) { var st = i < cols.L.Count ? cols.L[i] : null; cw[i] = st != null && st.SizeType == SizeType.Percent ? totW * st.Width / 100f : (st != null ? st.Width : totW / ColumnCount); }
            for (int i = 0; i < RowCount; i++) { var st = i < rows.L.Count ? rows.L[i] : null; rh[i] = st != null && st.SizeType == SizeType.Percent ? totH * st.Height / 100f : (st != null ? st.Height : totH / RowCount); }
            var cx = new float[ColumnCount + 1]; for (int i = 0; i < ColumnCount; i++) cx[i + 1] = cx[i] + cw[i];
            var cy = new float[RowCount + 1]; for (int i = 0; i < RowCount; i++) cy[i + 1] = cy[i] + rh[i];
            foreach (var c in items)
            {
                if (!cell.ContainsKey(c)) continue;
                int col = cell[c][0], row = cell[c][1]; int sp = span.ContainsKey(c) ? span[c] : 1;
                int ce = Math.Min(ColumnCount, col + sp);
                float px = cx[col] + c.Margin.Left, py = cy[row] + c.Margin.Top;
                float pw = cx[ce] - cx[col] - c.Margin.Horizontal, ph = (row + 1 <= RowCount ? cy[row + 1] : totH) - cy[row] - c.Margin.Vertical;
                c.SetBounds((int)Math.Round(px), (int)Math.Round(py), (int)Math.Round(pw), (int)Math.Round(ph));
            }
        }
    }

    public class ListBox : Control
    {
        public class ObjectCollection : IEnumerable
        {
            internal readonly List<object> L = new List<object>();
            public int Add(object o) { L.Add(o); return L.Count - 1; }
            public void AddRange(object[] a) { L.AddRange(a); }
            public void Insert(int i, object o) { L.Insert(i, o); }
            public void Clear() { L.Clear(); }
            public int Count { get { return L.Count; } }
            public object this[int i] { get { return L[i]; } }
            public IEnumerator GetEnumerator() { return L.GetEnumerator(); }
        }
        readonly ObjectCollection items = new ObjectCollection();
        public ObjectCollection Items { get { return items; } }
        public DrawMode DrawMode { get; set; }
        public BorderStyle BorderStyle { get; set; }
        public int ItemHeight { get; set; } = 18;
        public bool IntegralHeight { get; set; }
        public bool ScrollAlwaysVisible { get; set; }
        public int SelectedIndex { get; set; } = -1;
        public int TopIndex { get; set; }
        public object SelectedItem { get { return SelectedIndex >= 0 && SelectedIndex < items.Count ? items[SelectedIndex] : null; } }
        public event DrawItemEventHandler DrawItem;
        public void BeginUpdate() { } public void EndUpdate() { Invalidate(); }
        public void ClearSelected() { SelectedIndex = -1; }
        public Rectangle GetItemRectangle(int i) { return new Rectangle(0, (i - TopIndex) * ItemHeight, Width, ItemHeight); }
        protected override void OnPaint(PaintEventArgs e)
        {
            if (DrawItem == null) return;
            int vis = ItemHeight > 0 ? Height / ItemHeight + 1 : 0;
            for (int i = TopIndex; i < items.Count && i < TopIndex + vis; i++)
            {
                var r = new Rectangle(0, (i - TopIndex) * ItemHeight, Width, ItemHeight);
                DrawItem(this, new DrawItemEventArgs(e.Graphics, Font, r, i, i == SelectedIndex ? DrawItemState.Selected : 0));
            }
        }
        protected override void OnMouseDown(MouseEventArgs e)
        {
            if (ItemHeight <= 0) return;
            int idx = TopIndex + e.Y / ItemHeight;
            if (idx >= 0 && idx < items.Count) { SelectedIndex = idx; RaiseSelectedIndexChanged(); Invalidate(); }
        }
        protected override void OnMouseWheel(MouseEventArgs e) { TopIndex = Math.Max(0, Math.Min(Math.Max(0, items.Count - 1), TopIndex - Math.Sign(e.Delta))); Invalidate(); }
    }

    public class TextBoxBase : Control
    {
        protected string text = "";
        public int TextLength { get { return text.Length; } }
        public bool ReadOnly { get; set; }
        public bool WordWrap { get; set; }
        public int SelectionStart { get; set; }
        public int SelectionLength { get; set; }
        public new BorderStyle BorderStyle { get; set; }
        public void Clear() { text = ""; Invalidate(); }
        public void AppendText(string s) { text += s; Invalidate(); }
        public void ScrollToCaret() { }
        public new string Text { get { return text; } set { text = value ?? ""; Invalidate(); } }
    }
    public class TextBox : TextBoxBase
    {
        public event EventHandler TextChanged;
        protected override void OnKeyDown(KeyEventArgs e) { }
        internal void TypeChar(char ch) { text += ch; if (TextChanged != null) TextChanged(this, EventArgs.Empty); Invalidate(); }
    }
    public class RichTextBox : TextBoxBase
    {
        public bool DetectUrls { get; set; }
        public RichTextBoxScrollBars ScrollBars { get; set; }
        public Color SelectionColor { get; set; } = Color.FromArgb(176, 236, 186);
        public Font SelectionFont { get; set; }
        struct Run { public string T; public Color C; public bool Bold; public bool NL; }
        readonly List<Run> runs = new List<Run>();
        int scroll;
        public RichTextBox() { BackColor = Color.FromArgb(3, 7, 4); }
        public new void Clear() { runs.Clear(); scroll = 0; base.Clear(); }
        public new void AppendText(string s)
        {
            bool bold = SelectionFont != null && (SelectionFont.Style & FontStyle.Bold) != 0;
            var parts = (s ?? "").Replace("\r", "").Split('\n');
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i].Length > 0) runs.Add(new Run { T = parts[i], C = SelectionColor, Bold = bold });
                if (i < parts.Length - 1) runs.Add(new Run { NL = true });
            }
            Invalidate();
        }
        public string Rtf { set { ParseRtf(value); Invalidate(); } }
        void ParseRtf(string rtf)
        {
            runs.Clear(); scroll = 0;
            if (string.IsNullOrEmpty(rtf)) return;
            var colors = new List<Color>();
            int ct = rtf.IndexOf("\\colortbl");
            if (ct < 0) ct = rtf.IndexOf("colortbl");
            if (ct >= 0)
            {
                int end = rtf.IndexOf('}', ct);
                string seg = end > ct ? rtf.Substring(ct, end - ct) : rtf.Substring(ct);
                foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(seg, @"\\red(\d+)\\green(\d+)\\blue(\d+)"))
                    colors.Add(Color.FromArgb(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value)));
            }
            int bodyStart = rtf.IndexOf("\\f0\\fs");
            int ci = bodyStart >= 0 ? rtf.IndexOf(' ', bodyStart) : 0;
            Color cur = SelectionColor; bool bold = false; var sb = new System.Text.StringBuilder();
            Action flush = null; flush = () => { if (sb.Length > 0) { runs.Add(new Run { T = sb.ToString(), C = cur, Bold = bold }); sb.Clear(); } };
            for (int i = Math.Max(0, ci); i < rtf.Length; i++)
            {
                char c = rtf[i];
                if (c == '\\')
                {
                    i++; if (i >= rtf.Length) break; char k = rtf[i];
                    if (k == '\\' || k == '{' || k == '}') { sb.Append(k); continue; }
                    int js = i; while (i < rtf.Length && char.IsLetter(rtf[i])) i++;
                    string word = rtf.Substring(js, i - js); string num = "";
                    bool neg = i < rtf.Length && rtf[i] == '-'; if (neg) i++;
                    while (i < rtf.Length && char.IsDigit(rtf[i])) { num += rtf[i]; i++; }
                    if (i < rtf.Length && rtf[i] == '?') { } else i--;
                    if (word == "cf") { flush(); int n = num.Length > 0 ? int.Parse(num) : 0; if (n >= 1 && n <= colors.Count) cur = colors[n - 1]; }
                    else if (word == "b") { flush(); bold = num != "0"; }
                    else if (word == "par") { flush(); runs.Add(new Run { NL = true }); }
                    else if (word == "u") { int code = num.Length > 0 ? int.Parse(num) * (neg ? -1 : 1) : 0; if (code < 0) code += 65536; sb.Append((char)code); }
                }
                else if (c == '{' || c == '}') { }
                else if (c == '\n' || c == '\r') { }
                else sb.Append(c);
            }
            flush();
        }
        protected override void OnMouseWheel(MouseEventArgs e) { scroll = Math.Max(0, scroll - Math.Sign(e.Delta) * 3); Invalidate(); }
        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics; var baseF = Font ?? new Font("__mono__", 9f);
            float lh = baseF.LineHeight; float pad = 6, x = pad, y = pad - scroll * lh; float maxw = Width - pad * 2;
            using (var fr = new Font(baseF.Name, baseF.SizeInPoints, FontStyle.Regular))
            using (var fb = new Font(baseF.Name, baseF.SizeInPoints, FontStyle.Bold))
            {
                foreach (var r in runs)
                {
                    if (r.NL) { x = pad; y += lh; continue; }
                    var f = r.Bold ? fb : fr; using (var br = new SolidBrush(r.C))
                    {
                        foreach (var word in SplitKeep(r.T))
                        {
                            float ww = f.MeasureText(word);
                            if (x + ww > pad + maxw && x > pad) { x = pad; y += lh; }
                            if (y + lh > 0 && y < Height) g.DrawString(word, f, br, new RectangleF(x, y, ww + 4, lh), new StringFormat(StringFormatFlags.NoWrap | StringFormatFlags.NoClip));
                            x += ww;
                        }
                    }
                }
            }
        }
        static IEnumerable<string> SplitKeep(string t)
        {
            int i = 0; while (i < t.Length) { int sp = t.IndexOf(' ', i); if (sp < 0) { yield return t.Substring(i); break; } yield return t.Substring(i, sp - i + 1); i = sp + 1; }
        }
    }

    public class Timer : IDisposable
    {
        int interval = 100; bool on; object dt;
        public event EventHandler Tick;
        public int Interval { get { return interval; } set { interval = Math.Max(1, value); Host.Retime(this); } }
        public bool Enabled { get { return on; } set { if (value) Start(); else Stop(); } }
        public void Start() { on = true; Host.AddTimer(this); }
        public void Stop() { on = false; Host.RemoveTimer(this); }
        internal void Fire() { if (on && Tick != null) Tick(this, EventArgs.Empty); }
        internal int Ms { get { return interval; } }
        internal object Native { get { return dt; } set { dt = value; } }
        public void Dispose() { Stop(); }
    }

    public static class Application
    {
        public static string ExecutablePath { get { return System.Reflection.Assembly.GetEntryAssembly().Location; } }
        public static event EventHandler Idle;
        public static void EnableVisualStyles() { }
        public static void SetCompatibleTextRenderingDefault(bool b) { }
        public static void SetUnhandledExceptionMode(UnhandledExceptionMode m) { }
        public static event System.Threading.ThreadExceptionEventHandler ThreadException { add { } remove { } }
        public static void AddMessageFilter(IMessageFilter f) { Host.Filters.Add(f); }
        public static void RemoveMessageFilter(IMessageFilter f) { Host.Filters.Remove(f); }
        public static void Run(Form f)
        {
            var rp = Environment.GetEnvironmentVariable("COG_RENDER");
            if (!string.IsNullOrEmpty(rp)) { Host.RenderOnce(f, rp); return; }
            Host.Run(f);
        }
    }

    public class Screen
    {
        public Rectangle WorkingArea;
        public static Screen PrimaryScreen { get { return new Screen { WorkingArea = Host.PrimaryWorkArea() }; } }
        public static Screen[] AllScreens { get { return new[] { PrimaryScreen }; } }
        public static Screen FromControl(Control c) { return PrimaryScreen; }
    }
    public static class TextRenderer
    {
        public static Size MeasureText(string s, Font f) { return new Size((int)Math.Ceiling(f.MeasureText(s ?? "")), (int)Math.Ceiling(f.LineHeight)); }
    }

    public static class SystemInformation
    {
        public static Size SmallIconSize { get { return new Size(16, 16); } }
        public static int VerticalScrollBarWidth { get { return 16; } }
    }

    public static class MessageBox
    {
        public static DialogResult Show(string text, string caption, MessageBoxButtons b, MessageBoxIcon i) { Console.Error.WriteLine("[MSG] " + caption + ": " + text); return DialogResult.OK; }
        public static DialogResult Show(IWin32Window o, string text, string caption, MessageBoxButtons b, MessageBoxIcon i) { return Show(text, caption, b, i); }
    }

    public class ProfessionalColorTable
    {
        public virtual Color ToolStripDropDownBackground { get { return Color.Black; } }
        public virtual Color ImageMarginGradientBegin { get { return Color.Black; } }
        public virtual Color ImageMarginGradientMiddle { get { return Color.Black; } }
        public virtual Color ImageMarginGradientEnd { get { return Color.Black; } }
        public virtual Color MenuBorder { get { return Color.Gray; } }
        public virtual Color MenuItemBorder { get { return Color.Gray; } }
        public virtual Color MenuItemSelected { get { return Color.DimGray; } }
        public virtual Color SeparatorDark { get { return Color.Gray; } }
        public virtual Color SeparatorLight { get { return Color.Black; } }
    }
    public class ToolStripRenderer { }
    public class ToolStripProfessionalRenderer : ToolStripRenderer { public ToolStripProfessionalRenderer(ProfessionalColorTable t) { } }
    public class ToolStripItem { public string Text { get; set; } public Color ForeColor { get; set; } public bool Enabled { get; set; } = true; public event EventHandler Click; internal void DoClick() { if (Click != null) Click(this, EventArgs.Empty); } }
    public class ToolStripMenuItem : ToolStripItem { public ToolStripMenuItem(string t) { Text = t; } }
    public class ToolStripSeparator : ToolStripItem { }
    public class ToolStripItemCollection { internal readonly List<ToolStripItem> L = new List<ToolStripItem>(); public int Add(ToolStripItem i) { L.Add(i); return L.Count - 1; } }
    public class ToolStrip { readonly ToolStripItemCollection items = new ToolStripItemCollection(); public ToolStripItemCollection Items { get { return items; } } public ToolStripRenderer Renderer { get; set; } public Font Font { get; set; } }
    public class ToolStripDropDown : ToolStrip { public void Show(Control c, Point p) { Host.ShowMenu(this, c, p); } }
    public class ToolStripDropDownMenu : ToolStripDropDown { public bool ShowImageMargin { get; set; } }
    public class ContextMenuStrip : ToolStripDropDownMenu { }

    public class NotifyIcon : IDisposable
    {
        public Icon Icon { get; set; }
        public string Text { get; set; }
        public bool Visible { get; set; }
        public ContextMenuStrip ContextMenuStrip { get; set; }
        public event EventHandler DoubleClick, BalloonTipClicked;
        public void ShowBalloonTip(int ms, string title, string text, ToolTipIcon icon) { Host.Notify(title, text); }
        public void Dispose() { }
    }

    public class CommonDialog : IDisposable { public virtual DialogResult ShowDialog(IWin32Window o) { return DialogResult.Cancel; } public void Dispose() { } }
    public class FileDialog : CommonDialog { public string FileName { get; set; } = ""; public string Filter { get; set; } public string InitialDirectory { get; set; } }
    public class SaveFileDialog : FileDialog { }
}
