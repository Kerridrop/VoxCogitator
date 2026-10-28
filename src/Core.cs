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
    class Verdict
    {
        public string Headline, Side;
        public Color Color;
        public List<string> Tips = new List<string>();
    }

    class PingRes
    {
        public string Target; public int Sent, Recv, Loss; public double Avg, Min, Max, Jitter;
    }

    class Hop { public int Num, Loss; public string Rtt, Addr, Asn, AsName; public Owner Own; }

    class ResResult { public string Name, Url, Ip, Route; public bool Ok; public long Ms; }

    enum Owner { None, Router, Provider, Transit, Server, Target, Beyond, Outer }

    class Diag
    {
        [DllImport("iphlpapi.dll")] static extern int GetBestInterface(uint dwDestAddr, out uint pdwBestIfIndex);
        [DllImport("iphlpapi.dll")] static extern int SendARP(uint destIp, uint srcIp, byte[] mac, ref int macLen);

        static string ArpMac(string ip, string src)
        {
            try
            {
                uint d = BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes(), 0);
                uint sIp = src != null ? BitConverter.ToUInt32(IPAddress.Parse(src).GetAddressBytes(), 0) : 0;
                for (int attempt = 0; attempt < 2; attempt++)
                {
                    var mac = new byte[6]; int len = 6;
                    if (SendARP(d, attempt == 0 ? sIp : 0, mac, ref len) == 0 && len == 6) return string.Join(":", mac.Select(b => b.ToString("X2")));
                }
            }
            catch { }
            return null;
        }

        const string PrivateRx = @"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)";
        static readonly string[] PublicTargets = { "1.1.1.1", "8.8.8.8", "77.88.8.8" };
        static readonly string[] DnsNames = { "ya.ru", "google.com" };
        static readonly string[] HttpsUrls = { "https://www.gstatic.com/generate_204", "https://ya.ru" };

        readonly string serverCfg, pattern; string isp; readonly int sshPort;
        public string DetectedIsp;
        string IspSfx { get { return string.IsNullOrEmpty(isp) ? "" : " (" + isp + ")"; } }
        void LearnIsp(string asn) { var n = AsName(asn); if (n != null) { DetectedIsp = n; isp = n; } }
        readonly Action<string, string> L; readonly Action<string> S;

        NetworkInterface phys, vpnNi; bool physSearched; string gwIp, myIp; bool isWifi; int signal = -1; PingRes gw; bool gwSilent; int gwPort;
        List<PingRes> pub = new List<PingRes>();
        bool pingOk, httpsOk, internetOk, dnsSysOk, dnsCfOk; string pubIp;
        double pathLoss = -1; bool ipMismatch;
        bool vpnUp, tunnelDead, tunnelAlive, probeOk, routeViaVpn = true, routeChecked;
        bool directKnown, directOk; long directMs; string directVia;
        bool gwArp, killSwitch, tunnelDownSeen, pathViaTunnel; string gwMac;
        List<ResResult> resResults; bool captive; string proxyInUse; int vpnIdx = -2; double speedMbit = -1; int speedFreezeKB = -1; string speedSrc;
        string serverIp; PingRes srv; bool sshOk, serverReachable;
        List<Hop> hops = new List<Hop>(); string ppText; bool ppProblem, ppRan, ppFromTunnel, ppHidden; Owner ppOwner = Owner.None;

        public Diag(string server, int ssh, string pattern, string isp, Action<string, string> log, Action<string> sec)
        {
            serverCfg = (server ?? "").Trim(); sshPort = ssh; this.pattern = pattern; this.isp = isp; L = log; S = sec;
        }

        public string Probe(out Color c)
        {
            FindPhys();
            if (Store.Stealth) { c = Theme.GreenDim; return Loc.T("СКРЫТНЫЙ РЕЖИМ — СЕРВЕР НЕ ПРОЩУПЫВАЕТСЯ"); }
            string ip = ResolveIp(serverCfg);
            if (ip == null) { c = Theme.Red; return Loc.T("АДРЕС НЕ РАЗРЕШАЕТСЯ"); }
            var r = Bypass ? PingVia(ip, 3, myIp) : PingStats(ip, 3, 1000, 32, false, 100);
            bool ssh = Bypass ? TcpOkVia(ip, sshPort, 2500, myIp) : TcpOk(ip, sshPort, 2500);
            if (r.Recv > 0 || ssh)
            {
                c = Theme.Green;
                return (r.Recv > 0 ? Loc.T("ЖИВ · ") + Math.Round(r.Avg) + Loc.T(" МС") : Loc.T("ЖИВ")) + (ssh ? Loc.T(" · SSH ДА") : Loc.T(" · SSH НЕТ"));
            }
            c = Theme.Red;
            return Bypass ? Loc.T("МОЛЧИТ (ИЛИ KILL SWITCH)") : Loc.T("МОЛЧИТ");
        }

        public Verdict Run(int mode)
        {
            tlsFailSeen = false;
            switch (mode)
            {
                case 1: CheckLocal(); CheckInternet(); return VerdictQuick();
                case 5: FindPhys(); CheckLoss(); return VerdictLoss();
                case 2: FindPhys(); CheckVpn(); return VerdictVpn();
                case 3: FindPhys(); CheckPath(); return VerdictPath();
                default: CheckLocal(); CheckInternet(); CheckSpeed(); CheckVpn(); CheckPath(); CheckMtu(); return VerdictFull();
            }
        }

        public static Action<string, double> Sampler;
        [ThreadStatic] public static bool NoSample;

        public static PingRes PingStats(string target, int count, int timeout = 1000, int size = 32, bool df = false, int delay = 100)
        {
            var res = new PingRes { Target = target, Sent = count };
            var times = new List<double>();
            using (var p = new Ping())
            {
                var opt = new PingOptions(64, df);
                var buf = new byte[size];
                for (int i = 0; i < count; i++)
                {
                    double sample = -1;
                    try { var r = p.Send(target, timeout, buf, opt); if (r.Status == IPStatus.Success) { times.Add(r.RoundtripTime); sample = r.RoundtripTime; } } catch { }
                    if (!df && !NoSample && Sampler != null) { try { Sampler(target, sample); } catch { } }
                    if (delay > 0) Thread.Sleep(delay);
                }
            }
            res.Recv = times.Count;
            res.Loss = (int)Math.Round(100.0 * (count - res.Recv) / count);
            if (res.Recv > 0)
            {
                res.Avg = Math.Round(times.Average(), 1); res.Min = times.Min(); res.Max = times.Max();
                if (res.Recv > 1)
                {
                    double d = 0; for (int i = 1; i < times.Count; i++) d += Math.Abs(times[i] - times[i - 1]);
                    res.Jitter = Math.Round(d / (times.Count - 1), 1);
                }
            }
            return res;
        }

        void ShowPing(string label, PingRes r, int warnMs)
        {
            if (r.Recv == 0) { L("fail", string.Format(Loc.T("{0} ({1}): не отвечает (потери 100%)"), label, r.Target)); return; }
            string t = string.Format(Loc.T("{0} ({1}): потери {2}%, пинг {3} мс ({4}–{5}), джиттер {6} мс"), label, r.Target, r.Loss, r.Avg, r.Min, r.Max, r.Jitter);
            if (r.Loss >= 20) L("fail", t);
            else if (r.Loss >= 5 || r.Avg > warnMs || r.Jitter > 30) L("warn", t);
            else L("ok", t);
        }

        static Encoding OemEnc()
        {
            try { return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage); } catch { return Encoding.Default; }
        }

        static string RunProcess(string file, string args, int timeoutMs)
        {
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
                    StandardOutputEncoding = OemEnc(), StandardErrorEncoding = OemEnc()
                };
                using (var p = Process.Start(psi))
                {
                    var o = p.StandardOutput.ReadToEndAsync();
                    p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch { } }
                    return o.Wait(3000) ? o.Result : "";
                }
            }
            catch { return ""; }
        }

        [ThreadStatic] public static int LastStatus;
        static volatile bool tlsFailSeen;

        internal static bool HttpOk(string url, int timeoutMs, bool readBody, out long ms, out string body)
        {
            var sw = Stopwatch.StartNew(); body = null; LastStatus = 0;
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = timeoutMs; req.ReadWriteTimeout = timeoutMs; req.UserAgent = "Cogitator/1.0";
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    LastStatus = (int)resp.StatusCode;
                    if (readBody) using (var sr = new StreamReader(resp.GetResponseStream())) body = sr.ReadToEnd();
                }
                ms = sw.ElapsedMilliseconds; return true;
            }
            catch (WebException ex)
            {
                ms = sw.ElapsedMilliseconds;
                if (ex.Status == WebExceptionStatus.TrustFailure || ex.Status == WebExceptionStatus.SecureChannelFailure) tlsFailSeen = true;
                if (ex.Response != null)
                {
                    var hr = ex.Response as HttpWebResponse;
                    if (hr != null) LastStatus = (int)hr.StatusCode;
                    try { ex.Response.Close(); } catch { }
                    return true;
                }
                return false;
            }
            catch { ms = sw.ElapsedMilliseconds; return false; }
        }

        static bool DnsQuery(string server, string name, int timeoutMs, out long ms)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var q = new List<byte>();
                int id = new Random().Next(1, 65535);
                q.Add((byte)(id >> 8)); q.Add((byte)id); q.Add(0x01); q.Add(0x00);
                q.AddRange(new byte[] { 0, 1, 0, 0, 0, 0, 0, 0 });
                foreach (var part in name.Split(new[] { '.' })) { var b = Encoding.ASCII.GetBytes(part); q.Add((byte)b.Length); q.AddRange(b); }
                q.Add(0); q.AddRange(new byte[] { 0, 1, 0, 1 });
                using (var u = new UdpClient())
                {
                    u.Client.ReceiveTimeout = timeoutMs;
                    u.Connect(server, 53);
                    u.Send(q.ToArray(), q.Count);
                    IPEndPoint ep = null;
                    var r = u.Receive(ref ep);
                    ms = sw.ElapsedMilliseconds;
                    return r.Length > 12 && r[0] == q[0] && r[1] == q[1] && (r[3] & 0x0F) == 0 && ((r[6] << 8) | r[7]) > 0;
                }
            }
            catch { ms = sw.ElapsedMilliseconds; return false; }
        }

        static bool TcpOkVia(string host, int port, int timeout, string src)
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    if (src != null) s.Bind(new IPEndPoint(IPAddress.Parse(src), 0));
                    var ar = s.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeout)) return false;
                    s.EndConnect(ar);
                    return s.Connected;
                }
            }
            catch { return false; }
        }

        static void FillStats(PingRes res, List<double> times)
        {
            res.Recv = times.Count;
            res.Loss = (int)Math.Round(100.0 * (res.Sent - res.Recv) / res.Sent);
            if (res.Recv > 0)
            {
                res.Avg = Math.Round(times.Average(), 1); res.Min = times.Min(); res.Max = times.Max();
                if (res.Recv > 1)
                {
                    double d = 0; for (int i = 1; i < times.Count; i++) d += Math.Abs(times[i] - times[i - 1]);
                    res.Jitter = Math.Round(d / (times.Count - 1), 1);
                }
            }
        }

        static PingRes PingVia(string target, int count, string src)
        {
            var res = new PingRes { Target = target, Sent = count };
            var times = new List<double>();
            var o = RunProcess("ping", "-n " + count + " -w 1000 -S " + src + " " + target, count * 1500 + 5000);
            foreach (var line in o.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var m = Regex.Match(line, @"[=<](\d+)\D{0,6}\s+TTL=", RegexOptions.IgnoreCase);
                if (!m.Success) continue;
                double v = double.Parse(m.Groups[1].Value);
                times.Add(v);
                if (!NoSample && Sampler != null) { try { Sampler(target, v); } catch { } }
            }
            for (int i = times.Count; i < count; i++) if (!NoSample && Sampler != null) { try { Sampler(target, -1); } catch { } }
            FillStats(res, times);
            return res;
        }

        bool Bypass { get { return vpnUp && myIp != null; } }

        void DirectCheck()
        {
            if (directKnown || !Bypass) return;
            directKnown = true;
            foreach (var t in new[] { new[] { "77.88.8.8", "53" }, new[] { "1.1.1.1", "443" }, new[] { "8.8.8.8", "443" } })
            {
                var sw = Stopwatch.StartNew();
                if (TcpOkVia(t[0], int.Parse(t[1]), 3000, myIp)) { directOk = true; directMs = sw.ElapsedMilliseconds; directVia = t[0] + ":" + t[1]; break; }
            }
            if (!directOk && !killSwitch && !gwArp && gwIp != null)
            {
                bool gwOpen = false;
                foreach (var port in new[] { 80, 443, 53 }) if (TcpOk(gwIp, port, 1200)) { gwOpen = true; break; }
                if (!gwOpen) { gwMac = ArpMac(gwIp, myIp); if (gwMac != null) gwArp = true; }
            }
            if (directOk) L("ok", Loc.T("В обход туннеля (напрямую через провайдера) интернет есть: ") + directVia + Loc.T(" за ") + directMs + Loc.T(" мс — роутер и провайдер пропускают трафик"));
            else if (killSwitch || gwArp)
            {
                killSwitch = true;
                L("warn", Loc.T("Мимо туннеля трафик закрыт — kill switch держит оборону. Провайдера в обход VPN не проверить, но роутер жив (ARP)."));
            }
            else L("warn", Loc.T("В обход туннеля интернета тоже нет: либо его закрывает kill switch, либо проблема у роутера или провайдера."));
        }

        public static bool TcpOk(string host, int port, int timeout)
        {
            try
            {
                using (var c = new TcpClient())
                {
                    var ar = c.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeout)) return false;
                    c.EndConnect(ar);
                    return c.Connected;
                }
            }
            catch { return false; }
        }

        public static string ResolveIp(string h)
        {
            IPAddress a;
            if (IPAddress.TryParse(h, out a)) return a.ToString();
            try
            {
                var t = Task.Run(() => Dns.GetHostAddresses(h));
                if (!t.Wait(5000)) return null;
                var ip = t.Result.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
                return ip == null ? null : ip.ToString();
            }
            catch { return null; }
        }

        static string GetPublicIp()
        {
            foreach (var u in new[] { "https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com" })
            {
                long ms; string body;
                if (HttpOk(u, 6000, true, out ms, out body) && body != null)
                {
                    IPAddress a; var s = body.Trim();
                    if (IPAddress.TryParse(s, out a)) return s;
                }
            }
            return null;
        }

        string sysProxy;
        bool IsVpn(NetworkInterface n)
        {
            return Tun.Looks(n, pattern) || (vpnNi != null && n.Id == vpnNi.Id);
        }

        long[] IfBytes(string id)
        {
            try
            {
                var n = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(x => x.Id == id);
                if (n == null) return null;
                var s = n.GetIPStatistics();
                return new[] { s.BytesSent, s.BytesReceived };
            }
            catch { return null; }
        }

        void FindPhys()
        {
            if (physSearched) return;
            physSearched = true;
            NetworkInterface[] all;
            try { all = NetworkInterface.GetAllNetworkInterfaces(); } catch { all = new NetworkInterface[0]; }
            NetworkInterface anyKnown;
            vpnNi = Tun.Find(pattern, out anyKnown) ?? anyKnown;
            sysProxy = Tun.SystemProxy();
            vpnUp = vpnNi != null && vpnNi.OperationalStatus == OperationalStatus.Up;
            int bestIdx = -1;
            try { uint bi; if (GetBestInterface(BitConverter.ToUInt32(IPAddress.Parse("8.8.8.8").GetAddressBytes(), 0), out bi) == 0) bestIdx = (int)bi; } catch { }
            int bestScore = int.MinValue;
            foreach (var n in all)
            {
                if (n.OperationalStatus != OperationalStatus.Up) continue;
                if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback || n.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                if (IsVpn(n)) continue;
                IPInterfaceProperties props;
                try { props = n.GetIPProperties(); } catch { continue; }
                var g = props.GatewayAddresses.Select(x => x.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
                if (g == null) continue;
                int score = 0;
                try { if (props.GetIPv4Properties().Index == bestIdx) score += 100; } catch { }
                if (n.NetworkInterfaceType == NetworkInterfaceType.Ethernet || n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) score += 40;
                if (Regex.IsMatch(n.Name + " " + n.Description, "Hyper-V|vEthernet|VirtualBox|VMware|Virtual|Npcap|Bluetooth|TAP-|ZeroTier|Tailscale|Docker|WSL", RegexOptions.IgnoreCase)) score -= 80;
                if (score <= bestScore) continue;
                bestScore = score;
                phys = n; gwIp = g.ToString();
                myIp = props.UnicastAddresses.Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(u => u.Address.ToString()).FirstOrDefault();
                isWifi = n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ||
                         Regex.IsMatch(n.Description + " " + n.Name, @"802\.11|Wireless|Wi-?Fi|Беспровод", RegexOptions.IgnoreCase);
            }
        }

        string GetSystemDns()
        {
            var list = new List<NetworkInterface>();
            if (vpnUp && vpnNi != null) list.Add(vpnNi);
            if (phys != null) list.Add(phys);
            foreach (var n in list)
            {
                try
                {
                    var a = n.GetIPProperties().DnsAddresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
                    if (a != null) return a.ToString();
                }
                catch { }
            }
            return null;
        }

        void CheckLocal()
        {
            S(Loc.T("I. ДОМАШНИЙ АЛТАРЬ — ты → роутер"));
            FindPhys();
            if (phys == null) { L("fail", Loc.T("Нет активного подключения со шлюзом (кабель выдернут / Wi-Fi не подключён?)")); return; }
            string speed = phys.Speed > 0 ? (phys.Speed / 1000000) + Loc.T(" Мбит/с") : Loc.T("неизвестна");
            L("info", string.Format(Loc.T("Адаптер: {0} ({1}), скорость линка {2}"), phys.Name, isWifi ? "Wi-Fi" : Loc.T("кабель"), speed));
            L("info", string.Format(Loc.T("Твой IP: {0}   Шлюз (роутер): {1}"), myIp, gwIp));
            if (isWifi)
            {
                var o = RunProcess("netsh", "wlan show interfaces", 8000);
                var m = Regex.Match(o, @"(\d{1,3})\s*%");
                if (m.Success)
                {
                    signal = int.Parse(m.Groups[1].Value);
                    if (signal < 50) L("warn", Loc.T("Сигнал Wi-Fi: ") + signal + Loc.T("% — слабый: подойди к роутеру, переключись на 5 ГГц или кабель"));
                    else L("ok", Loc.T("Сигнал Wi-Fi: ") + signal + "%");
                }
            }
            gw = PingStats(gwIp, 20, 1000, 32, false, 50);
            if (gw.Recv > 0) { ShowPing(Loc.T("Роутер"), gw, isWifi ? 30 : 10); return; }
            foreach (var port in new[] { 80, 443, 53 })
                if (TcpOk(gwIp, port, 1500)) { gwSilent = true; gwPort = port; break; }
            if (gwSilent)
                L("info", Loc.T("Роутер (") + gwIp + Loc.T(") не отвечает на ping, но откликается на TCP-порту ") + gwPort +
                    Loc.T(" — он жив, просто ответ на ping запрещён в его настройках. Это не ошибка."));
            else
            {
                gwMac = ArpMac(gwIp, myIp);
                if (gwMac != null)
                {
                    gwArp = true;
                    if (vpnUp)
                    {
                        killSwitch = true;
                        L("info", Loc.T("Роутер жив: отвечает на ARP (MAC ") + gwMac + Loc.T("), но ping и TCP до него не доходят — их режет kill switch VPN на этом ПК. Это не ошибка."));
                    }
                    else
                        L("info", Loc.T("Роутер жив: отвечает на ARP (MAC ") + gwMac + Loc.T("), но ping и TCP закрыты брандмауэром (на ПК или в роутере). Это не ошибка."));
                }
                else
                    L("warn", Loc.T("Роутер (") + gwIp + Loc.T(") не ответил и на ARP. Если интернет при этом работает — это особенность роутера или VPN-драйвера, а не обрыв; если интернета нет — проверь кабель, порт и роутер."));
            }
        }

        void CheckInternet()
        {
            S(Loc.T("II. ВНЕШНИЕ МИРЫ — интернет"));
            FindPhys();
            L("info", vpnUp ? Loc.T("VPN включён — эти проверки идут ЧЕРЕЗ туннель") : Loc.T("VPN выключен — проверки идут напрямую через провайдера"));
            foreach (var t in PublicTargets) { var r = PingStats(t, 10); ShowPing(Loc.T("Пинг"), r, 100); pub.Add(r); }
            pingOk = pub.Any(r => r.Recv > 0);

            try
            {
                var probe = new Uri("https://ya.ru/");
                var px = WebRequest.GetSystemWebProxy().GetProxy(probe);
                if (px != null && px.Host != probe.Host) { proxyInUse = px.Authority; L("info", Loc.T("В Windows включён прокси ") + px.Authority + Loc.T(" — HTTPS-проверки идут через него.")); }
            }
            catch { }
            foreach (var u in HttpsUrls)
            {
                long ms; string b;
                string shortU = u.Replace("https://", "");
                if (HttpOk(u, 8000, false, out ms, out b))
                {
                    httpsOk = true;
                    L(ms > 2000 ? "warn" : "ok", "HTTPS " + shortU + Loc.T(" — открывается (") + ms + Loc.T(" мс)"));
                    if (u.Contains("generate_204") && LastStatus != 0 && LastStatus != 204)
                    {
                        captive = true;
                        L("warn", Loc.T("Вместо пустого ответа 204 пришёл код ") + LastStatus + Loc.T(" — похоже на портал авторизации (captive portal): сеть требует входа в браузере."));
                    }
                }
                else L("fail", "HTTPS " + shortU + Loc.T(" — не открывается"));
            }
            if (!httpsOk && tlsFailSeen)
                L("warn", Loc.T("Ошибка защищённого соединения (TLS). Частые причины: сбитые дата и время Windows, антивирус с «проверкой HTTPS», подмена трафика."));
            internetOk = pingOk || httpsOk;
            if (vpnUp && !internetOk) { tunnelDownSeen = true; DirectCheck(); }

            string sysDns = GetSystemDns();
            foreach (var n in DnsNames)
            {
                long m1 = 0, m2;
                bool d1 = sysDns != null && DnsQuery(sysDns, n, 2500, out m1);
                bool d2 = DnsQuery("1.1.1.1", n, 2500, out m2);
                if (d1) dnsSysOk = true;
                if (d2) dnsCfOk = true;
                string who = sysDns != null ? Loc.T("твой DNS (") + sysDns + ")" : Loc.T("твой DNS (не настроен)");
                string s1 = d1 ? Loc.T("ок (") + m1 + Loc.T(" мс)") : Loc.T("НЕ ОТВЕЧАЕТ");
                string s2 = d2 ? Loc.T("ок (") + m2 + Loc.T(" мс)") : Loc.T("не отвечает");
                L(d1 ? "ok" : "fail", "DNS " + n + ": " + who + " " + s1 + Loc.T(", через 1.1.1.1 ") + s2);
            }

            pubIp = GetPublicIp();
            if (pubIp != null) L("info", Loc.T("Внешний IP: ") + pubIp);
            if (pubIp != null && !vpnUp) LearnIsp(AsnOf(pubIp));
            else L("warn", Loc.T("Внешний IP узнать не удалось: ни один из трёх сервисов (ipify, ifconfig.me, icanhazip) не ответил — признак выборочной недоступности"));
            if (internetOk) CheckResources();
        }

        static readonly string[][] Resources =
        {
            new[] { Loc.T("Яндекс"), "https://ya.ru" },
            new[] { "Google", "https://www.google.com/generate_204" },
            new[] { "YouTube", "https://www.youtube.com/generate_204" },
            new[] { "Telegram API", "https://api.telegram.org" },
            new[] { "Telegram DC", "tcp://149.154.167.51:443" },
            new[] { "Discord", "https://discord.com/api/v10/gateway" },
            new[] { "Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace" },
            new[] { "GitHub", "https://github.com" }
        };

        int VpnIndex()
        {
            if (vpnIdx == -2)
            {
                vpnIdx = -1;
                try { if (vpnUp && vpnNi != null) vpnIdx = vpnNi.GetIPProperties().GetIPv4Properties().Index; } catch { }
            }
            return vpnIdx;
        }

        string RouteOf(string ip)
        {
            if (!vpnUp || ip == null || VpnIndex() < 0) return null;
            try
            {
                uint idx;
                if (GetBestInterface(BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes(), 0), out idx) == 0)
                    return (int)idx == VpnIndex() ? Loc.T("через туннель") : Loc.T("мимо туннеля");
            }
            catch { }
            return null;
        }

        void CheckResources()
        {
            S(Loc.T("ВРАТА РЕСУРСОВ — открываются ли ключевые сервисы"));
            var list = new List<ResResult>();
            var threads = new List<Thread>();
            foreach (var r in Resources)
            {
                var res = new ResResult { Name = r[0], Url = r[1] };
                list.Add(res);
                var th = new Thread(() =>
                {
                    NoSample = true;
                    try
                    {
                        var sw = Stopwatch.StartNew();
                        if (res.Url.StartsWith("tcp://"))
                        {
                            var hp = res.Url.Substring(6).Split(new[] { ':' });
                            res.Ip = hp[0];
                            res.Route = RouteOf(res.Ip);
                            res.Ok = TcpOk(hp[0], int.Parse(hp[1]), 6000);
                        }
                        else
                        {
                            var host = new Uri(res.Url).Host;
                            res.Ip = ResolveIp(host);
                            res.Route = RouteOf(res.Ip);
                            long ms; string b;
                            res.Ok = res.Ip != null && HttpOk(res.Url, 7000, false, out ms, out b);
                        }
                        res.Ms = sw.ElapsedMilliseconds;
                    }
                    catch { res.Ok = false; }
                });
                th.IsBackground = true;
                threads.Add(th);
                th.Start();
            }
            foreach (var th in threads) th.Join(10000);
            foreach (var r in list)
            {
                string route = r.Route != null ? "  ·  " + r.Route : "";
                if (r.Ok) L(r.Ms > 2500 ? "warn" : "ok", r.Name + Loc.T(" — открывается (") + r.Ms + Loc.T(" мс)") + route);
                else L("fail", r.Name + Loc.T(" — НЕДОСТУПЕН") + (r.Ip == null ? Loc.T(" (адрес не разрешился)") : "") + route);
            }
            resResults = list;
        }

        void CheckSpeed()
        {
            if (!internetOk) return;
            S(Loc.T("ПОТОК ДАННЫХ — замер скорости и проверка на «заморозку»"));
            FindPhys();
            if (vpnUp)
            {
                L("info", Loc.T("При включённом VPN замер скорости не проводится: на линиях с ТСПУ крупная загрузка через туннель сама провоцирует его удушение и обрыв. Скорость через VPN — вратами с замером скорости, по твоей воле."));
                return;
            }
            string[] urls = { "https://speed.cloudflare.com/__down?bytes=4000000", "https://speedtest.selectel.ru/10MB" };
            foreach (var url in urls)
            {
                long bytes = 0; double secs = 0; bool stalled = false, started = false;
                var sw = Stopwatch.StartNew();
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(url);
                    req.Timeout = 8000; req.ReadWriteTimeout = 5000; req.UserAgent = "Cogitator/1.0";
                    using (var resp = req.GetResponse())
                    using (var st = resp.GetResponseStream())
                    {
                        started = true;
                        var buf = new byte[65536];
                        while (bytes < 4000000 && sw.Elapsed.TotalSeconds < 12)
                        {
                            int n = st.Read(buf, 0, buf.Length);
                            if (n <= 0) break;
                            bytes += n;
                        }
                    }
                }
                catch (IOException) { stalled = started; }
                catch (WebException ex) { stalled = started || ex.Status == WebExceptionStatus.Timeout && bytes > 0; }
                catch { }
                secs = Math.Max(0.001, sw.Elapsed.TotalSeconds);
                string src = new Uri(url).Host;
                if (bytes >= 500000)
                {
                    speedMbit = Math.Round(bytes * 8 / secs / 1000000, 1);
                    speedSrc = src;
                    L(speedMbit < 2 ? "warn" : "ok", Loc.T("Скорость загрузки: ") + speedMbit + Loc.T(" Мбит/с (") + (bytes / 1024) + Loc.T(" КБ с ") + src + ")" + (vpnUp ? Loc.T(" · через туннель") : ""));
                    return;
                }
                if (started && bytes < 128 * 1024)
                {
                    speedFreezeKB = (int)(bytes / 1024);
                    speedSrc = src;
                    L("fail", Loc.T("Загрузка с ") + src + Loc.T(" замерла после ") + speedFreezeKB + Loc.T(" КБ — соединение открылось, а поток встал. Так выглядит ТСПУ-«заморозка» или потеря крупных пакетов (MTU)."));
                    return;
                }
                L("info", src + Loc.T(" недоступен для замера") + (stalled ? Loc.T(" (обрыв на ") + (bytes / 1024) + Loc.T(" КБ)") : "") + Loc.T(", пробую другой источник..."));
            }
            L("warn", Loc.T("Замер скорости не удался: ни один источник не отдал данные."));
        }

        void CheckVpn()
        {
            S(Loc.T("III. СВЯТИЛИЩЕ VPN"));
            FindPhys();
            if (vpnNi != null) L("info", Loc.T("Адаптер VPN: ") + vpnNi.Name + " — " + (vpnUp ? Loc.T("включён") : Loc.T("выключен")));
            else L("info", Loc.T("Адаптер VPN не найден — VPN выключен (или поправь шаблон имени адаптера в settings.ini)"));
            if (!vpnUp && sysProxy != null)
                L("warn", Loc.T("Клиент VPN работает в режиме системного прокси (") + sysProxy + Loc.T("): туннеля нет. Через прокси идут браузеры и приложения, которые его уважают; ping, игры и голос Discord — напрямую. Для честной проверки включи в клиенте режим TUN."));

            if (vpnUp)
            {
                try
                {
                    uint idx;
                    uint addr = BitConverter.ToUInt32(IPAddress.Parse("1.1.1.1").GetAddressBytes(), 0);
                    if (GetBestInterface(addr, out idx) == 0)
                    {
                        int vIdx = vpnNi.GetIPProperties().GetIPv4Properties().Index;
                        routeChecked = true;
                        routeViaVpn = (int)idx == vIdx;
                        if (routeViaVpn) L("ok", Loc.T("Трафик в интернет идёт через туннель"));
                        else L("warn", Loc.T("Трафик в интернет идёт МИМО туннеля (split-tunnel?)"));
                    }
                }
                catch { }
            }

            long[] b1 = vpnUp ? IfBytes(vpnNi.Id) : null;
            var pr = PingStats("1.1.1.1", 8, 1000, 32, false, 120);
            if (pr.Recv > 0)
            {
                var more = PingStats("1.1.1.1", 22, 1000, 32, false, 120);
                var lost = (pr.Sent - pr.Recv) + (more.Sent - more.Recv);
                double avg = more.Recv > 0 ? Math.Round((pr.Avg * pr.Recv + more.Avg * more.Recv) / (pr.Recv + more.Recv), 1) : pr.Avg;
                pr = new PingRes { Target = "1.1.1.1", Sent = 30, Recv = 30 - lost, Loss = (int)Math.Round(100.0 * lost / 30), Avg = avg };
            }
            long hms; string hb;
            bool hok = HttpOk("https://www.gstatic.com/generate_204", 8000, false, out hms, out hb);
            probeOk = pr.Recv > 0 || hok;
            if (vpnUp) L(probeOk ? "ok" : "fail", probeOk ? Loc.T("Через туннель интернет есть") : Loc.T("Через туннель интернета НЕТ"));
            else L(probeOk ? "ok" : "fail", probeOk ? Loc.T("Интернет напрямую есть") : Loc.T("Интернета напрямую НЕТ"));
            if (pr.Recv > 0)
            {
                pathLoss = pr.Loss;
                string what = vpnUp ? Loc.T("Потери через туннель: ") : Loc.T("Потери напрямую: ");
                L(pr.Loss >= 3 ? "fail" : pr.Loss > 0 ? "warn" : "ok", what + pr.Loss + "% (" + (pr.Sent - pr.Recv) + Loc.T(" из ") + pr.Sent + ") · " + Loc.T("Пинг") + " " + pr.Avg + Loc.T(" мс"));
            }

            if (b1 != null)
            {
                var b2 = IfBytes(vpnNi.Id);
                if (b2 != null)
                {
                    long dS = b2[0] - b1[0], dR = b2[1] - b1[1];
                    if (dS == 0 && dR == 0) L("info", Loc.T("Счётчики трафика туннеля недоступны — тест живости пропущен"));
                    else if (dS > 200 && dR < 100)
                    {
                        tunnelDead = true;
                        L("fail", Loc.T("Туннель: отправлено ") + dS + Loc.T(" байт, получено ") + dR + Loc.T(" — сервер НЕ отвечает по VPN-протоколу"));
                    }
                    else { tunnelAlive = true; L("ok", Loc.T("Туннель живой: отправлено ") + dS + Loc.T(" байт, получено ") + dR); }
                }
            }

            if (vpnUp && (!probeOk || tunnelDead)) { tunnelDownSeen = true; DirectCheck(); }
            if (serverCfg.Length == 0) { L("warn", Loc.T("Адрес святилища (VPN-сервера) не указан — впиши его справа (он виден в клиенте Amnezia под названием сервера)")); return; }
            if (!Store.Stealth)
            {
                serverIp = ResolveIp(serverCfg);
                if (serverIp == null) { L("fail", Loc.T("Не удалось получить IP для «") + serverCfg + "»"); return; }
            }
            if (Store.Stealth)
            {
                serverReachable = vpnUp && tunnelAlive;
                L("info", Loc.T("Скрытный режим: сервер напрямую не прощупываю, чтобы не светить VPN провайдеру. Сужу по туннелю."));
            }
            else
            {
                srv = Bypass ? PingVia(serverIp, 10, myIp) : PingStats(serverIp, 20);
                sshOk = Bypass ? TcpOkVia(serverIp, sshPort, 3000, myIp) : TcpOk(serverIp, sshPort, 3000);
                if (Bypass && tunnelAlive && srv.Recv == 0 && !sshOk)
                {
                    L("info", Loc.T("Пинг и SSH до сервера в обход туннеля не проходят — скорее всего, их закрывает kill switch. Туннель при этом живой и получает ответы, значит сам сервер работает."));
                    serverReachable = true;
                }
                else
                {
                    ShowPing(Bypass ? Loc.T("Пинг сервера в обход туннеля") : Loc.T("Пинг сервера"), srv, 150);
                    if (sshOk) L("ok", Loc.T("Сервер принимает соединения на порту ") + sshPort + Loc.T(" (SSH) — сам сервер жив"));
                    else L("warn", Loc.T("Порт ") + sshPort + Loc.T(" (SSH) не отвечает"));
                    serverReachable = srv.Recv > 0 || sshOk || (vpnUp && tunnelAlive);
                }
                if (!serverReachable && directKnown && !directOk)
                    L("info", Loc.T("Проверить сервер не вышло: трафик мимо туннеля закрыт (kill switch), так что это ещё не значит, что сервер лежит."));
            }

            if (pubIp == null) pubIp = GetPublicIp();
            if (pubIp != null && vpnUp)
            {
                if (pubIp == serverIp) L("ok", Loc.T("Внешний IP ") + pubIp + Loc.T(" совпадает с сервером — ты выходишь в сеть через VPN"));
                else { ipMismatch = true; L("warn", Loc.T("Внешний IP ") + pubIp + Loc.T(" не совпадает с сервером (split-tunnel или у сервера другой выходной IP)")); }
            }
        }

        Owner HopOwner(int num, string addr, bool isTarget)
        {
            if (pathViaTunnel)
            {
                if (isTarget) return Owner.Target;
                return num <= 1 ? Owner.Server : Owner.Beyond;
            }
            if (isTarget) return serverIp != null ? Owner.Server : Owner.Target;
            if (addr != null && addr == gwIp) return Owner.Router;
            if (num <= 1) return Owner.Router;
            if (num <= 3 || (addr != null && Regex.IsMatch(addr, PrivateRx))) return Owner.Provider;
            return Owner.Transit;
        }

        string OwnerText(Owner o)
        {
            switch (o)
            {
                case Owner.Router: return Loc.T("твой роутер / домашняя сеть");
                case Owner.Provider: return Loc.T("сеть провайдера") + IspSfx;
                case Owner.Transit: return Loc.T("магистраль между провайдером и сервером");
                case Owner.Server: return Loc.T("VPN-сервер / дата-центр хостера");
                case Owner.Target: return Loc.T("конечный узел");
                case Owner.Beyond: return Loc.T("сеть за VPN-сервером (у хостера)");
                case Owner.Outer: return Loc.T("магистраль за хостером (до сайтов)");
                default: return Loc.T("неизвестно");
            }
        }

        static readonly Dictionary<string, string> asnCache = new Dictionary<string, string>(), asNameCache = new Dictionary<string, string>();

        static string DnsTxt(string name, int timeoutMs)
        {
            foreach (var server in new[] { "1.1.1.1", "8.8.8.8", "77.88.8.8" })
            {
                try
                {
                    var q = new List<byte>();
                    int id = new Random().Next(1, 65535);
                    q.Add((byte)(id >> 8)); q.Add((byte)id); q.Add(0x01); q.Add(0x00);
                    q.AddRange(new byte[] { 0, 1, 0, 0, 0, 0, 0, 0 });
                    foreach (var part in name.Split(new[] { '.' })) { var b = Encoding.ASCII.GetBytes(part); q.Add((byte)b.Length); q.AddRange(b); }
                    q.Add(0); q.AddRange(new byte[] { 0, 16, 0, 1 });
                    using (var u = new UdpClient())
                    {
                        u.Client.ReceiveTimeout = timeoutMs;
                        u.Connect(server, 53);
                        u.Send(q.ToArray(), q.Count);
                        IPEndPoint ep = null;
                        var r = u.Receive(ref ep);
                        if (r.Length < 12 || r[0] != q[0] || r[1] != q[1] || (r[3] & 0x0F) != 0) continue;
                        int an = (r[6] << 8) | r[7]; if (an == 0) return null;
                        int pos = 12;
                        while (pos < r.Length && r[pos] != 0) pos += r[pos] + 1;
                        pos += 5;
                        for (int a = 0; a < an && pos + 10 < r.Length; a++)
                        {
                            if ((r[pos] & 0xC0) == 0xC0) pos += 2; else { while (pos < r.Length && r[pos] != 0) pos += r[pos] + 1; pos++; }
                            int type = (r[pos] << 8) | r[pos + 1];
                            int len = (r[pos + 8] << 8) | r[pos + 9];
                            pos += 10;
                            if (type == 16 && pos + len <= r.Length)
                            {
                                var sb = new StringBuilder(); int e = pos + len, k = pos;
                                while (k < e) { int sl = r[k]; sb.Append(Encoding.ASCII.GetString(r, k + 1, Math.Min(sl, e - k - 1))); k += sl + 1; }
                                return sb.ToString();
                            }
                            pos += len;
                        }
                        return null;
                    }
                }
                catch { }
            }
            return null;
        }

        internal static string AsnOf(string ip)
        {
            if (ip == null || Regex.IsMatch(ip, PrivateRx)) return null;
            lock (asnCache) if (asnCache.ContainsKey(ip)) return asnCache[ip];
            string asn = null;
            try
            {
                var o = ip.Split(new[] { '.' });
                var t = DnsTxt(o[3] + "." + o[2] + "." + o[1] + "." + o[0] + ".origin.asn.cymru.com", 1500);
                if (t != null) { var f = t.Split(new[] { '|' })[0].Trim().Split(new[] { ' ' })[0]; if (Regex.IsMatch(f, @"^\d+$")) asn = f; }
            }
            catch { }
            lock (asnCache) asnCache[ip] = asn;
            return asn;
        }

        internal static string AsName(string asn)
        {
            if (asn == null) return null;
            lock (asNameCache) if (asNameCache.ContainsKey(asn)) return asNameCache[asn];
            string n = null;
            try
            {
                var t = DnsTxt("AS" + asn + ".asn.cymru.com", 1500);
                if (t != null) { var parts = t.Split(new[] { '|' }); if (parts.Length >= 5) { n = parts[4].Trim().Split(new[] { ' ' })[0].TrimEnd(new[] { ',' }); } }
            }
            catch { }
            lock (asNameCache) asNameCache[asn] = n;
            return n;
        }

        List<Hop> RunPathping(string target, string src)
        {
            var lines = new List<string>();
            var psi = new ProcessStartInfo("pathping.exe", "-4 -n -q 20 -p 100 -h 15 -w 800 " + (src != null ? "-i " + src + " " : "") + target)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
                StandardOutputEncoding = OemEnc(), StandardErrorEncoding = OemEnc()
            };
            using (var p = new Process { StartInfo = psi })
            {
                p.OutputDataReceived += (s, e) => { if (e.Data != null) lock (lines) lines.Add(e.Data); };
                p.ErrorDataReceived += (s, e) => { };
                p.Start(); p.BeginOutputReadLine(); p.BeginErrorReadLine();
                if (p.WaitForExit(240000)) p.WaitForExit();
                else { try { p.Kill(); } catch { } p.WaitForExit(3000); }
            }
            var rx = new Regex(@"^\s*(\d+)\s+(---|\d+\S*)\s+(\d+)/\s*(\d+)\s*=\s*(\d+)%\s+(\d+)/\s*(\d+)\s*=\s*(\d+)%\s+(\S+)");
            var res = new List<Hop>();
            lock (lines)
                foreach (var line in lines)
                {
                    var m = rx.Match(line);
                    if (m.Success) res.Add(new Hop { Num = int.Parse(m.Groups[1].Value), Rtt = m.Groups[2].Value, Loss = int.Parse(m.Groups[5].Value), Addr = m.Groups[9].Value });
                }
            return res;
        }

        void Classify(List<Hop> hs, string target, bool viaTunnel, string serverAsn)
        {
            Parallel.ForEach(hs.Where(h => !Regex.IsMatch(h.Addr, PrivateRx)).Select(h => h.Addr).Distinct().ToList(), new ParallelOptions { MaxDegreeOfParallelism = 6 }, ip => AsnOf(ip));
            foreach (var h in hs) { h.Asn = AsnOf(h.Addr); }
            string targetAsn = AsnOf(target);
            if (viaTunnel)
            {
                string hoster = serverAsn ?? hs.Where(h => h.Num > 1 && h.Asn != null).Select(h => h.Asn).FirstOrDefault();
                foreach (var h in hs)
                {
                    if (h.Addr == target) h.Own = Owner.Target;
                    else if (h.Num <= 1 || Regex.IsMatch(h.Addr, PrivateRx)) h.Own = Owner.Server;
                    else if (h.Asn != null && h.Asn == hoster) h.Own = Owner.Beyond;
                    else if (h.Asn != null && h.Asn == targetAsn) h.Own = Owner.Target;
                    else if (h.Asn == null && hs.Where(x => x.Num < h.Num).All(x => x.Own == Owner.Server || x.Own == Owner.Beyond)) h.Own = Owner.Beyond;
                    else h.Own = Owner.Outer;
                }
            }
            else
            {
                string ispAsn = hs.Where(h => h.Asn != null && h.Asn != serverAsn && h.Addr != target).Select(h => h.Asn).FirstOrDefault();
                if (ispAsn != null) LearnIsp(ispAsn);
                bool seenPublic = false;
                foreach (var h in hs)
                {
                    bool priv = Regex.IsMatch(h.Addr, PrivateRx);
                    if (h.Addr == target) h.Own = serverIp != null && target == serverIp ? Owner.Server : Owner.Target;
                    else if (h.Addr == gwIp || (h.Num == 1 && priv)) h.Own = Owner.Router;
                    else if (priv) h.Own = seenPublic ? Owner.Transit : Owner.Provider;
                    else if (h.Asn == null) h.Own = h.Num <= 3 ? Owner.Provider : Owner.Transit;
                    else if (h.Asn == ispAsn) h.Own = Owner.Provider;
                    else if (serverAsn != null && h.Asn == serverAsn) h.Own = Owner.Server;
                    else h.Own = Owner.Transit;
                    if (!priv) seenPublic = true;
                }
            }
            foreach (var h in hs) if (h.Asn != null) h.AsName = AsName(h.Asn);
        }

        bool pathNetOk;
        public List<Leg> Legs;
        public class Leg { public string Title, Target; public bool Tunnel, Blocked, Problem, Reached, Hidden; public List<Hop> Hops = new List<Hop>(); public Owner Own = Owner.None; public string Text; public Hop Origin; }

        void AnalyzeLeg(Leg lg)
        {
            var hs = lg.Hops;
            if (hs.Count == 0)
            {
                if (lg.Blocked || (!lg.Tunnel && vpnUp && pathNetOk))
                {
                    lg.Hidden = true;
                    lg.Text = Loc.T("Трассировка мимо туннеля не проходит: ICMP вне туннеля закрыт (kill switch клиента VPN). Участок дом → провайдер → хостер отсюда не виден — это не обрыв. Чтобы увидеть его, выключи VPN (или kill switch) и повтори ритуал III.");
                    return;
                }
                lg.Problem = !pathNetOk;
                lg.Hidden = pathNetOk;
                lg.Text = pathNetOk ? Loc.T("Ни один узел не ответил на трассировку, но интернет работает — ICMP где-то фильтруется. Маршрут скрыт, обрыва нет.") : Loc.T("pathping не смог построить маршрут — не ответил ни один узел.");
                return;
            }
            var last = hs[hs.Count - 1];
            lg.Reached = last.Addr == lg.Target;
            if (!lg.Reached)
            {
                if (!lg.Tunnel && serverIp != null && lg.Target == serverIp && sshOk)
                { lg.Text = Loc.T("Трасса не доходит до сервера по ICMP, но сервер отвечает по TCP — он просто игнорирует ping/трассировку, это нормально."); return; }
                lg.Own = last.Own == Owner.Router ? Owner.Provider : last.Own == Owner.Provider ? Owner.Transit
                       : last.Own == Owner.Server ? (lg.Tunnel ? Owner.Beyond : Owner.Server) : last.Own == Owner.Beyond ? Owner.Outer : last.Own;
                if (pathNetOk)
                {
                    lg.Hidden = true;
                    lg.Text = (lg.Tunnel && last.Own == Owner.Server
                        ? Loc.T("Трасса видна только до святилища: узлы за ним не отвечают на ICMP (сервер не пропускает служебные ответы трассировки). Интернет через туннель при этом работает — обрыва нет.")
                        : Loc.T("Узлы после ") + last.Num + " (" + last.Addr + Loc.T(") не отвечают на трассировку, но связь работает — это фильтрация ICMP, а не обрыв. Следующий участок: ") + OwnerText(lg.Own) + ".");
                    return;
                }
                lg.Problem = true;
                lg.Text = Loc.T("Маршрут обрывается после узла ") + last.Num + " (" + last.Addr + Loc.T("). Следующий участок: ") + OwnerText(lg.Own) + ".";
                lg.Origin = last;
                return;
            }
            if (last.Loss >= 5)
            {
                Hop first = last;
                for (int i = 0; i < hs.Count; i++)
                {
                    bool all = true;
                    for (int j = i; j < hs.Count; j++) if (hs[j].Loss < 5) { all = false; break; }
                    if (all) { first = hs[i]; break; }
                }
                lg.Problem = true; lg.Own = first.Own; lg.Origin = first;
                lg.Text = Loc.T("Потери до цели ") + last.Loss + Loc.T("%. Начинаются на узле ") + first.Num + " (" + first.Addr + Loc.T(") и тянутся до конца — виноват участок: ") + OwnerText(lg.Own) + ".";
                return;
            }
            lg.Text = Loc.T("До цели потерь нет (") + last.Loss + "%).";
            if (hs.Any(x => x.Loss >= 20)) lg.Text += Loc.T(" Красные промежуточные узлы — это роутеры, которые экономят на ответах ICMP; на связь не влияет.");
        }

        internal static string Short(Owner o)
        {
            switch (o)
            {
                case Owner.Router: return Loc.T("ДОМ");
                case Owner.Provider: return Loc.T("ПРОВАЙДЕР");
                case Owner.Transit: return Loc.T("МАГИСТРАЛЬ");
                case Owner.Server: return Loc.T("СВЯТИЛИЩЕ");
                case Owner.Beyond: return Loc.T("ХОСТЕР");
                case Owner.Outer: return Loc.T("ДАЛЬНЯЯ МАГИСТРАЛЬ");
                case Owner.Target: return Loc.T("ЦЕЛЬ");
                default: return "?";
            }
        }

        void PrintLeg(Leg lg)
        {
            S(lg.Title);
            if (lg.Hops.Count == 0) { L(lg.Problem ? "fail" : "info", lg.Text); return; }
            var cl = new List<List<Hop>>();
            foreach (var h in lg.Hops)
            {
                var c = cl.Count > 0 ? cl[cl.Count - 1] : null;
                string ca = c == null ? null : c.Select(x => x.Asn).FirstOrDefault(x => x != null);
                if (c == null || c[0].Own != h.Own || (h.Asn != null && ca != null && h.Asn != ca)) cl.Add(new List<Hop> { h });
                else c.Add(h);
            }
            int badIdx = lg.Problem && lg.Reached && lg.Origin != null ? cl.FindIndex(c => c.Contains(lg.Origin)) : -1;
            var map = new List<string>();
            for (int ci = 0; ci < cl.Count; ci++)
            {
                var c = cl[ci];
                var ah = c.FirstOrDefault(x => x.Asn != null);
                string own = !lg.Tunnel && c[0].Own == Owner.Server ? Loc.T("VPN-сервер / дата-центр хостера") : OwnerText(c[0].Own);
                L("info", "── " + own.ToUpperInvariant() + (ah != null ? " · AS" + ah.Asn + (ah.AsName != null ? " " + ah.AsName : "") : ""));
                foreach (var h in c)
                {
                    string line = string.Format(Loc.T("{0,2}. {1,-15}  rtt {2,-6} потери {3,3}%"), h.Num, h.Addr, h.Rtt, h.Loss) + (lg.Origin == h ? Loc.T("   ◄ ЗДЕСЬ НАЧИНАЕТСЯ ПОРЧА") : "");
                    L(h.Loss >= 20 ? "hop2" : h.Loss >= 5 ? "hop1" : "hop0", line);
                }
                string mark = badIdx < 0 ? "✓" : ci < badIdx ? "✓" : ci == badIdx ? "✗" : "·";
                string sh = !lg.Tunnel && c[0].Own == Owner.Server ? Loc.T("ХОСТЕР") : Short(c[0].Own);
                map.Add(sh + (ah != null && ah.AsName != null && c[0].Own != Owner.Router && c[0].Own != Owner.Target ? " (" + ah.AsName + ")" : "") + " " + mark);
            }
            if (!lg.Reached && (lg.Problem || lg.Hidden)) map.Add(Short(lg.Own) + (lg.Problem ? " ✗" : " ?"));
            L(lg.Problem ? "warn" : lg.Hidden ? "info" : "ok", Loc.T("Карта пути: ") + string.Join(" → ", map));
            L(lg.Problem ? "warn" : lg.Hidden ? "info" : "ok", lg.Text);
        }

        void CheckPath()
        {
            if (!Store.Stealth && serverIp == null && serverCfg.Length > 0) serverIp = ResolveIp(serverCfg);
            bool tunnelWorks = false;
            if (vpnUp)
            {
                tunnelWorks = (internetOk || probeOk) && !tunnelDead;
                if (!tunnelWorks && !tunnelDownSeen) tunnelWorks = PingStats("1.1.1.1", 3, 1000, 32, false, 100).Recv > 0;
                if (!tunnelWorks) { tunnelDownSeen = true; DirectCheck(); }
            }
            pathViaTunnel = vpnUp && tunnelWorks;
            if (!Store.Stealth && serverIp != null && !sshOk) sshOk = Bypass ? TcpOkVia(serverIp, sshPort, 3000, myIp) : TcpOk(serverIp, sshPort, 3000);
            pathNetOk = pathViaTunnel || (!vpnUp && (internetOk || PingStats("1.1.1.1", 3, 1000, 32, false, 100).Recv > 0 || TcpOk("1.1.1.1", 443, 2000)));

            var legs = new List<Leg>();
            bool traceServer = !Store.Stealth && serverIp != null;
            if (traceServer || !pathViaTunnel)
                legs.Add(new Leg { Target = traceServer ? serverIp : "1.1.1.1", Tunnel = false,
                    Title = traceServer ? Loc.T("ПУТЬ ДО СВЯТИЛИЩА — дом → провайдер → магистраль → хостер (") + serverIp + ")" : Loc.T("ПУТЬ ЧЕРЕЗ ВАРП — pathping до ") + "1.1.1.1" });
            if (pathViaTunnel)
                legs.Add(new Leg { Target = "1.1.1.1", Tunnel = true, Title = Loc.T("ПУТЬ ЗА СВЯТИЛИЩЕМ — через туннель до 1.1.1.1") });
            L("info", legs.Count > 1 ? Loc.T("Две трассы идут разом: до святилища мимо туннеля и через туннель дальше. Около минуты, не закрывай когитатор.") : Loc.T("Трассировка займёт около минуты. Не закрывай когитатор."));

            string serverAsn = traceServer ? AsnOf(serverIp) : null;
            try
            {
                Parallel.ForEach(legs, lg =>
                {
                    lg.Hops = RunPathping(lg.Target, !lg.Tunnel && Bypass ? myIp : null);
                    if (!lg.Tunnel && lg.Hops.Count == 0 && Bypass && directKnown && !directOk) lg.Blocked = true;
                });
                ppRan = true;
            }
            catch (Exception ex)
            {
                var ie = ex is AggregateException ? ((AggregateException)ex).InnerException : ex;
                ppText = ie is System.ComponentModel.Win32Exception ? Loc.T("pathping.exe не найден в системе — трассировка невозможна.") : Loc.T("Не удалось запустить pathping: ") + ie.Message;
                L("fail", ppText);
                return;
            }
            if (legs.Any(l => !l.Tunnel && l.Hops.Count == 0 && Bypass) && !directKnown) { DirectCheck(); foreach (var l in legs) if (!l.Tunnel && l.Hops.Count == 0 && directKnown && !directOk) l.Blocked = true; }
            foreach (var lg in legs) { Classify(lg.Hops, lg.Target, lg.Tunnel, serverAsn); AnalyzeLeg(lg); PrintLeg(lg); }
            Legs = legs;

            var a = legs.FirstOrDefault(l => !l.Tunnel); var b = legs.FirstOrDefault(l => l.Tunnel);
            hops = a != null && a.Hops.Count > 0 ? a.Hops : b != null ? b.Hops : new List<Hop>();
            var bad = legs.FirstOrDefault(l => l.Problem);
            if (bad != null) { ppProblem = true; ppOwner = bad.Own; ppText = bad.Text; ppFromTunnel = bad.Tunnel; }
            else { ppProblem = false; ppText = string.Join(" ", legs.Select(l => l.Text)); ppHidden = legs.All(l => l.Hidden || !l.Reached); }
        }

        void CheckMtu()
        {
            S(Loc.T("V. МЕРА СОСУДА — MTU"));
            Func<int, bool> ok = s => PingStats("1.1.1.1", 2, 1000, s, true, 0).Recv > 0;
            if (!ok(1000)) { L("warn", Loc.T("MTU не измерить (ping с запретом фрагментации не проходит)")); return; }
            int lo = 1000, hi = 1472;
            if (ok(hi)) lo = hi;
            while (hi - lo > 1) { int mid = (lo + hi) / 2; if (ok(mid)) lo = mid; else hi = mid; }
            int mtu = lo + 28;
            if (mtu >= 1500) L("ok", Loc.T("MTU пути: ") + mtu + Loc.T(" — без ограничений"));
            else if (vpnUp) L("info", Loc.T("MTU пути через VPN: ") + mtu + Loc.T(" (для туннеля это нормально — WireGuard съедает ~80 байт)"));
            else L("warn", Loc.T("MTU пути: ") + mtu + Loc.T(" — меньше 1500 (PPPoE у провайдера / туннель)"));
        }

        static Verdict V(string head, string side, Color c, params string[] tips)
        {
            var v = new Verdict { Headline = head, Side = side, Color = c };
            foreach (var t in tips) if (!string.IsNullOrEmpty(t)) v.Tips.Add(t);
            return v;
        }

        static readonly string HomeHead = Loc.T("ЕРЕСЬ В СТЕНАХ ТВОЕГО ДОМА");
        static readonly string IspHead = Loc.T("СКВЕРНА В СЕТИ ПРОВАЙДЕРА");

        Verdict LocalVerdict()
        {
            if (phys == null)
                return V(HomeHead, Loc.T("Виновата твоя сторона: нет подключения к сети"), Theme.Red,
                    Loc.T("Проверь кабель или подключись к Wi-Fi, включи адаптер. Если адаптер «завис» — перезагрузи ПК."));
            bool upstreamDead = vpnUp ? (directKnown && !directOk && !killSwitch) : !internetOk;
            if (gw != null && gw.Recv == 0 && !gwSilent && !gwArp && (gwMac == null) && (upstreamDead || !internetOk))
                return V(HomeHead, Loc.T("Виновата твоя сторона: роутер не отвечает даже на ARP"), Theme.Red,
                    Loc.T("Перезагрузи роутер: выдерни из розетки на 30 секунд."), Loc.T("Проверь, к той ли Wi-Fi сети ты подключён."));
            if (gw != null && gw.Recv > 0 && (gw.Loss >= 5 || (isWifi && gw.Jitter > 30)))
                return V(HomeHead, Loc.T("Виновата твоя сторона: нестабильная связь с роутером"), Theme.Red,
                    Loc.T("Потери уже между компом и роутером — провайдер тут ни при чём."),
                    isWifi ? Loc.T("Wi-Fi: подойди ближе, переключись на 5 ГГц, смени канал в роутере или подключи кабель.")
                           : Loc.T("Кабель: переткни или замени патч-корд, попробуй другой порт роутера."));
            return null;
        }

        Verdict DnsHttpsVerdict()
        {
            if (captive)
                return V(Loc.T("ВРАТА ПОД СТРАЖЕЙ"), Loc.T("Сеть требует авторизации в браузере (captive portal)"), Theme.Amber,
                    Loc.T("Открой любой сайт в браузере и пройди вход — так бывает в гостиницах, кафе и общественном Wi-Fi."));
            if (!httpsOk && tlsFailSeen)
                return V(Loc.T("ПЕЧАТЬ ПОДЛОГА"), Loc.T("Сайты не открываются из-за ошибки защищённого соединения (TLS)"), Theme.Amber,
                    Loc.T("Проверь дату и время: Параметры → Время и язык → «Синхронизировать»."),
                    Loc.T("Антивирус с функцией «проверка HTTPS / защищённых соединений» тоже может так ломать связь — отключи её на минуту и повтори."));
            if (!httpsOk && pingOk && proxyInUse != null)
                return V(Loc.T("ПРОКСИ ПРЕГРАЖДАЕТ ПУТЬ"), Loc.T("Пинг идёт, а сайты не открываются — а в Windows включён прокси ") + proxyInUse, Theme.Amber,
                    Loc.T("Отключи прокси: Параметры → Сеть и Интернет → Прокси-сервер, и повтори ритуал."));
            if (!dnsSysOk)
                return V(Loc.T("ДУХ ИМЁН БЕЗМОЛВСТВУЕТ"), Loc.T("Виноват DNS: интернет есть, но имена сайтов не определяются"), Theme.Amber,
                    dnsCfOk ? Loc.T("Через 1.1.1.1 DNS работает: пропиши в настройках адаптера или роутера DNS 1.1.1.1 и 8.8.8.8.")
                            : Loc.T("DNS не отвечает даже 1.1.1.1 — возможно, провайдер блокирует сторонние DNS. Попробуй DNS-over-HTTPS в браузере."));
            if (!httpsOk && pingOk)
                return V(Loc.T("ПЕЧАТИ НА ВРАТАХ"), Loc.T("Фильтрация: пинг идёт, а сайты не открываются"), Theme.Amber,
                    Loc.T("ICMP проходит, а HTTPS нет — похоже на блокировку трафика или прокси. Проверь с включённым VPN."));
            return null;
        }

        Verdict TunnelLossVerdict()
        {
            if (!vpnUp || pathLoss < 1) return null;
            var tips = new List<string>
            {
                Loc.T("Проверь, где теряется: соверши перекличку пакетов (V) с включённым VPN и с выключенным."),
                Loc.T("Без VPN чисто — потери вносит туннель. ТСПУ часто не блокирует VPN целиком, а «душит» его, роняя часть пакетов. Помогает смена протокола (например, на XRay / VLESS-Reality), порта или параметров обфускации в Amnezia."),
                Loc.T("Теряется и без VPN — дело в домашней линии или у провайдера: начни с ритуала I.")
            };
            if (pathLoss >= 3)
                return V(Loc.T("ТУННЕЛЬ ИСТЕКАЕТ ПАКЕТАМИ"), Loc.T("Туннель жив, но теряет ") + pathLoss + Loc.T("% пакетов — связь будет рваться, а сайты и мессенджеры подвисать"), Theme.Red, tips.ToArray());
            return V(Loc.T("ТУННЕЛЬ ТЕРЯЕТ ПАКЕТЫ"), Loc.T("Туннель жив, но теряет ") + pathLoss + Loc.T("% пакетов — в играх и звонках это будет заметно"), Theme.Amber, tips.ToArray());
        }

        Verdict FreezeVerdict()
        {
            if (speedFreezeKB < 0) return null;
            return V(Loc.T("ЗАМОРОЗКА ПОТОКА"), Loc.T("Мелкие запросы проходят, а загрузка замирает после ~") + speedFreezeKB + Loc.T(" КБ — поэтому «вроде есть связь, но ничего не грузится»"), Theme.Red,
                Loc.T("Так выглядит ТСПУ-«заморозка» соединений или потеря крупных пакетов (проблема MTU)."),
                vpnUp ? Loc.T("В Amnezia уменьши MTU до 1280 (настройки протокола AmneziaWG). Не помогло — смени протокол, например на XRay / VLESS-Reality.")
                      : Loc.T("Включи VPN и повтори великий ритуал: если с VPN поток идёт — это блокировка на стороне провайдера."));
        }

        Verdict ResourceVerdict()
        {
            if (resResults == null) return null;
            var bad = resResults.Where(r => !r.Ok).ToList();
            bool ipFail = pubIp == null;
            if (bad.Count == 0 && !ipFail) return null;
            var names = bad.Select(r => r.Name).ToList();
            if (ipFail) names.Add(Loc.T("сервисы определения IP"));
            var tips = new List<string>();
            var bypass = bad.Where(r => r.Route == Loc.T("мимо туннеля")).Select(r => r.Name).ToList();
            var tun = bad.Where(r => r.Route == Loc.T("через туннель")).Select(r => r.Name).ToList();
            if (vpnUp && bypass.Count > 0)
                tips.Add(Loc.T("Мимо туннеля идут и не открываются: ") + string.Join(", ", bypass) + Loc.T(". Это раздельное туннелирование: VPN их не касается, а провайдер режет. Добавь их в список туннеля в Amnezia или включи режим «весь трафик через VPN»."));
            if (vpnUp && tun.Count > 0)
                tips.Add(Loc.T("Через туннель не открываются: ") + string.Join(", ", tun) + Loc.T(". Либо сервер не выпускает к ним трафик, либо туннель теряет крупные пакеты — попробуй MTU 1280 в Amnezia и запусти великий ритуал: там есть замер скорости."));
            if (vpnUp && ipFail && bad.Count == 0)
                tips.Add(Loc.T("Все ключевые сервисы открываются, не отвечают только сервисы определения IP — скорее всего их режет раздельное туннелирование или фильтр на сервере. На работу это почти не влияет."));
            if (!vpnUp)
                tips.Add(Loc.T("Без VPN это обычно блокировка на стороне провайдера (РКН / ТСПУ). Включи VPN и повтори ритуал."));
            bool severe = bad.Count >= 3;
            return V(severe ? Loc.T("ВРАТА ЗАПЕЧАТАНЫ") : Loc.T("ЧАСТЬ ВРАТ ЗАПЕЧАТАНА"), Loc.T("Интернет есть, но недоступны: ") + string.Join(", ", names), severe ? Theme.Red : Theme.Amber, tips.ToArray());
        }

        Verdict QualityVerdict()
        {
            var w = new List<string>();
            if (signal >= 0 && signal < 50) w.Add(Loc.T("Слабый сигнал Wi-Fi (") + signal + "%).");
            if (pub.Any(r => r.Recv > 0 && (r.Avg > 150 || r.Jitter > 30 || r.Loss >= 5))) w.Add(Loc.T("Высокий пинг, джиттер или потери до публичных серверов."));
            if (speedMbit >= 0 && speedMbit < 2) w.Add(Loc.T("Низкая скорость загрузки: ") + speedMbit + Loc.T(" Мбит/с."));
            if (srv != null && srv.Recv > 0 && (srv.Avg > 150 || srv.Jitter > 30)) w.Add(Loc.T("До VPN-сервера высокий пинг или джиттер (") + srv.Avg + Loc.T(" мс / ") + srv.Jitter + Loc.T(" мс)."));
            if (w.Count > 0) return V(Loc.T("ДУХ ВОРЧИТ"), Loc.T("Связь работает, но качество так себе"), Theme.Amber, w.ToArray());
            return V(Loc.T("МАШИННЫЙ ДУХ ДОВОЛЕН"), Loc.T("Всё в порядке"), Theme.Green,
                Loc.T("Если что-то конкретное не работает — скорее всего, проблема на стороне сайта или сервиса."));
        }

        static readonly string TspuFix = Loc.T("Обход: в клиенте Amnezia смени протокол (например, на XRay / VLESS-Reality), смени порт или параметры обфускации AmneziaWG.");
        static readonly string TspuServerCheck = Loc.T("Исключи сервер: по SSH sudo docker ps — контейнер amnezia-awg должен быть Up. Если Up — сервер ни при чём.");
        static readonly string TspuMobile = Loc.T("Контрольный опыт: подключись к VPN через мобильный интернет. Работает там — режут на домашней линии.");

        Verdict TunnelDownVerdict()
        {
            if (directKnown && !directOk && killSwitch)
                return V(Loc.T("ТУННЕЛЬ ПАЛ"), Loc.T("VPN не отвечает, а kill switch закрыл всё мимо туннеля — поэтому интернета нет совсем"), Theme.Red,
                    tunnelDead ? Loc.T("Пакеты в туннель уходят, ответов ноль. Роутер жив (ответил на ARP), кабель в порядке — дело в туннеле.") : Loc.T("Роутер жив (ответил на ARP), кабель в порядке — дело в туннеле."),
                    Loc.T("Причины: ТСПУ режет VPN-протокол (самое частое) или упал сервер."),
                    Loc.T("Проверка без снятия kill switch: подключись к VPN с телефона через мобильный интернет. Работает — режут домашнюю линию; не работает нигде — сервер."),
                    Loc.T("Или нажми «Отключить» в Amnezia (kill switch обычно снимается вместе с подключением) и запусти ритуал II — когитатор проверит провайдера и сервер напрямую."),
                    TspuFix);
            if (directKnown && !directOk)
                return V(IspHead, Loc.T("Интернета нет ни через VPN, ни в обход него — проблема до VPN"), Theme.Red,
                    Loc.T("Роутер или провайдер не пропускают трафик. Выключи VPN и запусти ритуал I."),
                    Loc.T("Если без VPN интернет есть — проверь, не включён ли в клиенте kill switch (он блокирует трафик мимо туннеля)."));
            if (serverIp != null && serverReachable)
                return V(Loc.T("ТСПУ ДУШИТ ТУННЕЛЬ"), Loc.T("Интернет в обход VPN есть, сервер жив, но VPN-протокол не проходит — почти наверняка блокировка ТСПУ"), Theme.Red,
                    tunnelDead ? Loc.T("Пакеты в туннель уходят, а ответов ноль: провайдер пропускает всё, кроме самого VPN.") : null,
                    TspuServerCheck, TspuFix, TspuMobile);
            if (serverIp != null)
                return V(Loc.T("СВЯТИЛИЩЕ НЕДОСТИЖИМО"), Loc.T("Интернет в обход VPN есть, но до сервера не достучаться"), Theme.Red,
                    Loc.T("Либо сервер лежит (панель хостера: включён, оплачен?), либо ТСПУ заблокировал IP сервера целиком."),
                    TspuMobile.Replace(Loc.T("Работает там — режут на домашней линии."), Loc.T("Доступен там — блокировка на домашней линии; нигде — сервер.")), ppText);
            if (directOk)
                return V(Loc.T("ТУННЕЛЬ ЗАДУШЕН"), Loc.T("Интернет в обход VPN есть, а через VPN — нет"), Theme.Red,
                    tunnelDead ? Loc.T("Пакеты в туннель уходят, а ответов ноль. Чаще всего это ТСПУ режет VPN-протокол, реже — упал сервер.") : Loc.T("Туннель не выпускает в интернет."),
                    Loc.T("Впиши адрес сервера справа (он виден в клиенте Amnezia) — когитатор проверит, жив ли сервер, и уточнит приговор."),
                    TspuFix);
            return V(Loc.T("ДУХ ТУННЕЛЯ БЕЗМОЛВСТВУЕТ"), Loc.T("VPN включён, но интернета через него нет"), Theme.Red,
                Loc.T("Впиши адрес сервера справа и запусти ритуал II или IV для точного диагноза."));
        }

        Verdict NatVerdict()
        {
            return V(Loc.T("СВЯТИЛИЩЕ НЕ ВЫПУСКАЕТ В МИР"), Loc.T("Виноват VPN-сервер: туннель есть, а интернета через него нет"), Theme.Red,
                Loc.T("Сервер принимает подключение, но не выпускает трафик наружу: NAT, форвардинг или DNS на сервере, либо проблемы у хостера."),
                Loc.T("По SSH: ping 1.1.1.1 с самого сервера и sudo docker ps; перезапусти контейнер или переустанови протокол из клиента Amnezia."));
        }

        Verdict OwnerVerdict(Owner o, string text, Color c)
        {
            var v = OwnerVerdictRaw(o, text, c);
            if (o != Owner.None) v.Tips.Add(Loc.T("Одна трассировка — снимок момента. Если картина повторяется в нескольких прогонах, вывод надёжен."));
            return v;
        }

        Verdict OwnerVerdictRaw(Owner o, string text, Color c)
        {
            switch (o)
            {
                case Owner.Router:
                    return V(HomeHead, Loc.T("Потери начинаются у тебя: роутер / домашняя сеть"), c, text, Loc.T("Перезагрузи роутер, проверь кабели и Wi-Fi."));
                case Owner.Provider:
                    return V(IspHead, Loc.T("Потери начинаются в сети провайдера") + IspSfx, c, text, Loc.T("Звони в поддержку провайдера и назови узел, с которого начинаются потери (сохрани отчёт)."));
                case Owner.Transit:
                    return V(Loc.T("ПОРЧА В ПУСТОТЕ МЕЖДУ МИРАМИ"), Loc.T("Потери начинаются на магистрали между провайдером и сервером — не у тебя и не у провайдера напрямую"), c, text,
                        Loc.T("Обычно это проходит само. Если держится часами — пиши провайдеру с отчётом или смени локацию сервера."));
                case Owner.Server:
                    if (pathViaTunnel && ppFromTunnel)
                        return V(Loc.T("ПОТЕРИ НА ПУТИ К СВЯТИЛИЩУ"), Loc.T("Пакеты теряются уже до VPN-сервера: домашняя линия, провайдер (в т.ч. ТСПУ) или сам сервер"), c, text,
                            Loc.T("Запусти ритуал III с выключенным VPN — трасса до сервера через провайдера покажет точный участок."));
                    return V(Loc.T("СВЯТИЛИЩЕ ОСКВЕРНЕНО"), Loc.T("Похоже, порча на VPN-сервере или у хостера"), c, text,
                        Loc.T("Зайди в панель хостера: сервер включён, оплачен, IP не сменился? Проверь нагрузку на сервере."));
                case Owner.Target:
                    return V(Loc.T("ПОРЧА У ЦЕЛИ"), Loc.T("Проблема у конечного узла"), c, text);
                case Owner.Beyond:
                    return V(Loc.T("ПОРЧА ЗА СВЯТИЛИЩЕМ"), Loc.T("Потери начинаются за VPN-сервером — в сети хостера, а не у тебя и не у провайдера"), c, text,
                        Loc.T("Это участок от сервера до интернета. Если держится — напиши хостеру или смени локацию сервера."));
                case Owner.Outer:
                    return V(Loc.T("ПОРЧА ЗА ПРЕДЕЛАМИ СВЯТИЛИЩА"), Loc.T("Потери начинаются на магистрали за хостером — не у тебя, не у провайдера и не на самом сервере"), c, text,
                        Loc.T("Обычно проходит само. Если держится — сервер в другой локации или у другого хостера обойдёт этот участок."));
                default:
                    return V(Loc.T("МАРШРУТ НЕ ПОСТРОЕН"), Loc.T("Ни один узел не ответил — похоже, интернета нет вообще"), Theme.Red, text, Loc.T("Запусти ритуал I — он покажет, роутер это или провайдер."));
            }
        }

        Verdict VerdictQuick()
        {
            var v = LocalVerdict(); if (v != null) return v;
            if (!internetOk)
            {
                if (vpnUp) return TunnelDownVerdict();
                return V(IspHead, Loc.T("Виноват провайдер") + IspSfx + Loc.T(": роутер отвечает, а дальше пакеты не идут"), Theme.Red,
                    Loc.T("Перезагрузи роутер, проверь кабель провайдера в порту WAN и баланс в личном кабинете."),
                    Loc.T("Запусти ритуал III — он покажет, на каком узле обрыв. С этим и звони в поддержку."));
            }
            return DnsHttpsVerdict() ?? ResourceVerdict() ?? QualityVerdict();
        }

        Verdict VerdictVpn()
        {
            var v = LocalVerdict(); if (v != null) return v;
            bool hasServer = serverIp != null;
            if (vpnUp)
            {
                if (!probeOk && tunnelAlive && serverReachable) return NatVerdict();
                if (!probeOk || tunnelDead) return TunnelDownVerdict();
                if (routeChecked && !routeViaVpn)
                    return V(Loc.T("ДУХ ВОРЧИТ"), Loc.T("VPN включён, но трафик идёт мимо него"), Theme.Amber,
                        Loc.T("Похоже на раздельное туннелирование (split-tunnel) — проверь настройки клиента Amnezia."));
                if (srv != null && srv.Recv > 0 && (srv.Avg > 150 || srv.Jitter > 30 || srv.Loss >= 5))
                    return V(Loc.T("ДУХ ВОРЧИТ"), Loc.T("VPN работает, но связь с сервером так себе"), Theme.Amber,
                        Loc.T("До сервера: пинг ") + srv.Avg + Loc.T(" мс, джиттер ") + srv.Jitter + Loc.T(" мс, потери ") + srv.Loss + "%.",
                        Loc.T("Ритуал III покажет, на каком участке теряется качество."));
                var tlv = TunnelLossVerdict(); if (tlv != null) return tlv;
                if (ipMismatch)
                    return V(Loc.T("СВЯТИЛИЩЕ БЛАГОСЛОВЕННО"), Loc.T("VPN работает: туннель живой, интернет через него есть"), Theme.Green,
                        Loc.T("Внешний IP не совпадает с активным святилищем. Если это не другой выходной адрес сервера — проверь, что в Amnezia подключён тот же сервер, что выбран в когитаторе."));
                return V(Loc.T("СВЯТИЛИЩЕ БЛАГОСЛОВЕННО"), Loc.T("VPN работает: туннель живой, интернет через него есть"), Theme.Green);
            }
            if (!probeOk)
                return V(Loc.T("ВНЕШНИЕ МИРЫ НЕДОСТУПНЫ"), Loc.T("Интернета нет даже без VPN"), Theme.Red,
                    Loc.T("VPN тут ни при чём. Запусти ритуал I — он покажет, роутер это или провайдер."));
            if (hasServer && !serverReachable)
                return V(Loc.T("СВЯТИЛИЩЕ МОЛЧИТ"), Loc.T("Виноват VPN-сервер / хостер: интернет есть, а сервер недоступен"), Theme.Red,
                    Loc.T("Сервер не отвечает ни на ping, ни на SSH. Панель хостера: включён? оплачен? IP не сменился?"),
                    Loc.T("Ритуал III покажет, где обрывается путь."));
            if (hasServer)
                return V(Loc.T("СВЯТИЛИЩЕ ЖДЁТ"), Loc.T("Сервер жив, просто VPN выключен"), Theme.Green,
                    Loc.T("Включи подключение в клиенте Amnezia и запусти ритуал II ещё раз, чтобы проверить туннель."));
            return V(Loc.T("VPN ВЫКЛЮЧЕН"), Loc.T("Интернет напрямую есть, VPN не включён"), Theme.Amber,
                Loc.T("Впиши адрес сервера сверху, чтобы проверять и само святилище."));
        }

        PingRes lossRes; double lossPct, lossEff; int lossMaxStreak, lossBursts, lossEffLost, lossEffSent; string lossNote;

        void CheckLoss()
        {
            const int N = 120;
            string[] targets = { "1.1.1.1", "8.8.8.8", "77.88.8.8" };
            S(Loc.T("V. ПЕРЕКЛИЧКА ПАКЕТОВ — ") + (vpnUp ? Loc.T("через туннель") : Loc.T("напрямую через провайдера")));
            L("info", (vpnUp ? Loc.T("VPN включён — замеряю путь через туннель, именно так сейчас идёт твой трафик.")
                             : Loc.T("VPN выключен — замеряю прямой путь через провайдера.")) + " " + N + Loc.T(" пакетов по трём узлам, ~30 с."));
            if (isWifi) L("info", Loc.T("Ты на Wi-Fi: если потери найдутся, для чистоты эксперимента повтори замер по кабелю."));

            var times = new List<double>();
            int lost = 0, streak = 0, sent = 0;
            var perSent = new int[3]; var perLost = new int[3];
            var perTimes = new[] { new List<double>(), new List<double>(), new List<double>() };
            using (var p = new Ping())
            {
                var buf = new byte[32];
                var opt = new PingOptions(64, false);
                for (int i = 0; i < N; i++)
                {
                    int k = i % 3; string t = targets[k];
                    double sample = -1;
                    var sw = Stopwatch.StartNew();
                    try { var r = p.Send(t, 1000, buf, opt); if (r.Status == IPStatus.Success) sample = r.RoundtripTime; } catch { }
                    if (!NoSample && Sampler != null) { try { Sampler(t, sample); } catch { } }
                    perSent[k]++; sent++;
                    if (sample < 0)
                    {
                        lost++; perLost[k]++; streak++;
                        if (streak == 1) lossBursts++;
                        if (streak > lossMaxStreak) lossMaxStreak = streak;
                    }
                    else { streak = 0; times.Add(sample); perTimes[k].Add(sample); }
                    if ((i + 1) % 30 == 0)
                    {
                        double pc = Math.Round(100.0 * lost / (i + 1), 1);
                        L(pc >= 3 ? "fail" : pc > 0 ? "warn" : "ok", Loc.T("Отсчёт ") + (i + 1) + "/" + N + Loc.T(": потеряно ") + lost + " (" + pc + "%)");
                    }
                    if (sent == 15 && lost == 15) { L("fail", Loc.T("15 пакетов подряд не вернулись — связи нет, перекличку прекращаю.")); break; }
                    int rest = 250 - (int)sw.ElapsedMilliseconds;
                    if (rest > 0) Thread.Sleep(rest);
                }
            }
            lossRes = new PingRes { Target = Loc.T("3 узла"), Sent = sent };
            FillStats(lossRes, times);
            double jSum = 0; int jCnt = 0;
            for (int k = 0; k < 3; k++)
            {
                var pt = perTimes[k];
                for (int j = 1; j < pt.Count; j++) { jSum += Math.Abs(pt[j] - pt[j - 1]); jCnt++; }
            }
            lossRes.Jitter = jCnt > 0 ? Math.Round(jSum / jCnt, 1) : 0;
            lossPct = Math.Round(100.0 * lost / Math.Max(1, sent), 1);

            lossEff = lossPct; lossEffLost = lost; lossEffSent = sent;
            for (int k = 0; k < 3; k++)
            {
                if (perSent[k] == 0) continue;
                double mine = 100.0 * perLost[k] / perSent[k];
                int oL = 0, oS = 0;
                for (int j = 0; j < 3; j++) if (j != k) { oL += perLost[j]; oS += perSent[j]; }
                if (oS == 0) continue;
                double others = 100.0 * oL / oS;
                if (mine >= 20 && others <= 2)
                {
                    lossEff = Math.Round(others, 1); lossEffLost = oL; lossEffSent = oS;
                    lossNote = Loc.T("Почти все потери — только до ") + targets[k] + Loc.T(": этот узел просто режет ping, к твоему каналу это не относится.");
                }
            }

            if (times.Count > 0)
            for (int k = 0; k < 3; k++)
                L(perLost[k] == 0 ? "ok" : "warn", targets[k] + Loc.T(": потеряно ") + perLost[k] + Loc.T(" из ") + perSent[k]);
            if (lossRes.Recv > 0)
            {
                var parts = new List<string>();
                for (int k = 0; k < 3; k++)
                    if (perTimes[k].Count > 0) parts.Add(targets[k] + " — " + Math.Round(perTimes[k].Average()) + Loc.T(" мс"));
                L("info", Loc.T("Задержка по узлам: ") + string.Join(", ", parts) + Loc.T(". Джиттер (дрожание внутри каждого узла): ") + lossRes.Jitter + Loc.T(" мс"));
            }
            if (lost > 0 && times.Count > 0)
                L(lossMaxStreak >= 5 ? "warn" : "info", lossMaxStreak >= 5
                    ? Loc.T("Потери пачками: до ") + lossMaxStreak + Loc.T(" пакетов подряд (") + lossBursts + Loc.T(" провалов) — это кратковременные обрывы, а не просто шум.")
                    : Loc.T("Потери россыпью: ") + lossBursts + Loc.T(" провалов, максимум ") + lossMaxStreak + Loc.T(" подряд."));
            if (lossNote != null) L("info", lossNote);
            L(lossEff >= 3 ? "fail" : lossEff > 0 ? "warn" : "ok", Loc.T("Итог: потери ") + lossEff + "%" + (lossEff != lossPct ? Loc.T(" (с учётом узла-молчуна; сырые ") + lossPct + "%)" : ""));
        }

        static void Wilson(int x, int n, out double lo, out double hi)
        {
            lo = hi = 0; if (n <= 0) return;
            double z = 1.96, z2 = z * z, p = (double)x / n, d = 1 + z2 / n;
            double c = (p + z2 / (2 * n)) / d, h = z * Math.Sqrt(p * (1 - p) / n + z2 / (4.0 * n * n)) / d;
            lo = Math.Max(0, c - h) * 100; hi = Math.Min(1, c + h) * 100;
        }

        Verdict VerdictLoss()
        {
            var v = VerdictLossRaw();
            if (lossRes != null && lossRes.Recv > 0 && lossEffSent > 0)
            {
                double lo, hi; Wilson(lossEffLost, lossEffSent, out lo, out hi);
                v.Tips.Add(lossEffLost > 0
                    ? Loc.T("Замер — снимок за ~30 с (") + lossEffSent + Loc.T(" пакетов): с 95% уверенностью реальные потери от ") + Math.Round(lo, 1) + Loc.T("% до ") + Math.Round(hi, 1) + Loc.T("%. Для долгой картины — Ауспик или повтор переклички.")
                    : Loc.T("Замер — снимок за ~30 с (") + lossEffSent + Loc.T(" пакетов): реальные потери, скорее всего, ниже ") + Math.Round(hi, 1) + Loc.T("%. Для долгой картины — Ауспик."));
            }
            return v;
        }

        Verdict VerdictLossRaw()
        {
            if (phys == null) return LocalVerdict();
            string path = vpnUp ? Loc.T("через туннель") : Loc.T("напрямую через провайдера");
            if (lossRes == null || lossRes.Recv == 0)
                return V(Loc.T("СВЯЗИ НЕТ"), Loc.T("Ни один пакет не вернулся (") + path + ")", Theme.Red,
                    vpnUp ? Loc.T("Запусти ритуал II — он проверит, жив ли туннель и сервер.") : Loc.T("Запусти ритуал I — он покажет, роутер это или провайдер."));
            var tips = new List<string>();
            if (lossMaxStreak >= 5) tips.Add(Loc.T("Потери идут пачками до ") + lossMaxStreak + Loc.T(" пакетов подряд — похоже на кратковременные обрывы: Wi-Fi, кабель, перегрузка канала или туннель переподключается."));
            if (lossNote != null) tips.Add(lossNote);
            if (lossEff > 0)
            {
                if (vpnUp) tips.Add(Loc.T("Чтобы понять, где теряется: повтори перекличку с выключенным VPN. Без VPN чисто — потери в туннеле (сервер, хостер или ТСПУ); теряются и без него — домашняя линия или провайдер."));
                else tips.Add(Loc.T("Ритуал III покажет, на каком узле маршрута начинаются потери."));
                if (isWifi) tips.Add(Loc.T("Ты на Wi-Fi — сначала исключи его: повтори замер по кабелю."));
            }
            if (lossRes.Jitter > 30) tips.Add(Loc.T("Джиттер ") + lossRes.Jitter + Loc.T(" мс — задержка сильно скачет, это тоже бьёт по играм и звонкам."));

            if (lossEff >= 3)
                return V(Loc.T("ПАКЕТЫ ГИБНУТ"), Loc.T("Потери ") + lossEff + "% " + path + Loc.T(" — это уже заметно везде: обрывы звонков, лаги, медленная загрузка"), Theme.Red, tips.ToArray());
            if (lossEff >= 1)
                return V(Loc.T("ПАКЕТЫ ТЕРЯЮТСЯ"), Loc.T("Потери ") + lossEff + "% " + path + Loc.T(" — для сайтов терпимо, в играх и звонках будет заметно"), Theme.Amber, tips.ToArray());
            if (lossEff > 0)
                return V(Loc.T("ПОЧТИ ЧИСТО"), Loc.T("Единичные потери (") + lossEff + "%) " + path + Loc.T(" — в пределах нормы"), Theme.Green, tips.ToArray());
            return V(Loc.T("ПЕРЕКЛИЧКА СОШЛАСЬ"), Loc.T("Потерь нет: все пакеты вернулись ") + path + Loc.T(" · джиттер ") + lossRes.Jitter + Loc.T(" мс"), tips.Count > 0 ? Theme.Amber : Theme.Green, tips.ToArray());
        }

        Verdict VerdictPath()
        {
            var v = LocalVerdict(); if (v != null) return v;
            if (vpnUp && tunnelDownSeen) return TunnelDownVerdict();
            if (!ppRan) return V(Loc.T("ТРАССИРОВКА НЕ УДАЛАСЬ"), Loc.T("pathping не запустился"), Theme.Amber, ppText);
            if (ppProblem) return OwnerVerdict(ppOwner, ppText, ppOwner == Owner.None ? Theme.Red : Theme.Amber);
            if (ppHidden)
            {
                var tl = Legs != null ? Legs.FirstOrDefault(l => l.Tunnel) : null;
                int gwLoss = tl != null && tl.Hops.Count > 0 ? tl.Hops[0].Loss : -1;
                string gwHint = gwLoss >= 15
                    ? (pathViaTunnel
                        ? Loc.T("Потери на шлюзе туннеля ") + gwLoss + Loc.T("% — но туннель работает: это деприоритизация ICMP самим шлюзом, не реальная потеря.")
                        : Loc.T("Потери на шлюзе туннеля ") + gwLoss + Loc.T("% при неподтверждённом туннеле — возможна реальная просадка, проверь ритуалом V."))
                    : null;
                string ks = killSwitch
                    ? Loc.T("Килл-свитч режет входящий ICMP промежуточных узлов — наружную трассу отсюда не построить. Это норма, не поломка.")
                    : Loc.T("Узлы на пути не отвечают на трассировку (ICMP погашен) — это их настройка, не обрыв.");
                string beyond = pathViaTunnel ? Loc.T("За святилищем сервер не форвардит trace-ответы — ожидаемо. Интернет через туннель есть, обрыва нет.") : null;
                string mapHint = vpnUp ? Loc.T("Чтобы увидеть карту дом → провайдер → хостер — выключи VPN (или kill switch) и повтори ритуал III.") : null;
                string roll = Loc.T("Перекличка пакетов (V) покажет, есть ли потери вообще.");
                bool reach = pathViaTunnel || sshOk || serverReachable;
                if (pathViaTunnel && reach)
                    return V(Loc.T("ПУТЬ ДО СВЯТИЛИЩА ОТКРЫТ"), Loc.T("Святилище отвечает, туннель несёт трафик — связь в порядке. Пошаговую карту пути скрывает защита, а не поломка."), Theme.Green,
                        ks, beyond, gwHint, mapHint, roll);
                if (reach)
                    return V(Loc.T("СВЯТИЛИЩЕ ОТВЕЧАЕТ, ПУТЬ НЕ РАЗГЛЯДЕТЬ"), Loc.T("Прямые пробы подтверждают святилище, но трасса пуста — туннель не подтверждён. Запусти ритуал V (перекличка) для потерь."), Theme.Amber,
                        ks, gwHint, mapHint, roll);
                return V(Loc.T("ПУТЬ СКРЫТ ТУМАНОМ"), Loc.T("Связь не подтверждается и трасса пуста — запусти ритуал IV для полной картины."), Theme.Amber,
                    ks, mapHint, roll);
            }
            return V(Loc.T("ПУТЬ ЧИСТ"), Loc.T("Потерь на маршруте нет"), Theme.Green, ppText);
        }

        Verdict VerdictFull()
        {
            var v = LocalVerdict(); if (v != null) return v;
            if (!internetOk)
            {
                if (vpnUp)
                {
                    if (tunnelAlive && serverReachable) return NatVerdict();
                    return TunnelDownVerdict();
                }
                if (hops.Count <= 1)
                    return V(IspHead, Loc.T("Виноват провайдер") + IspSfx + Loc.T(" или вход интернета в роутер"), Theme.Red,
                        Loc.T("Роутер отвечает, но дальше пакеты не идут: роутер не получает интернет."),
                        Loc.T("Перезагрузи роутер, проверь кабель провайдера в порту WAN и баланс. Не помогло — звони в поддержку."), ppText);
                return V(IspHead, Loc.T("Виноват провайдер") + IspSfx, Theme.Red,
                    Loc.T("Домашняя сеть в порядке, обрыв дальше. Звони в поддержку и назови узел обрыва (сохрани отчёт)."), ppText);
            }
            var d = DnsHttpsVerdict(); if (d != null) return d;
            if (serverIp != null && !serverReachable)
                return V(Loc.T("СВЯТИЛИЩЕ МОЛЧИТ"), Loc.T("Виноват VPN-сервер / хостер: интернет есть, а сервер недоступен"), Theme.Red,
                    Loc.T("Сервер не отвечает ни на ping, ни на SSH. Панель хостера: включён? оплачен? IP не сменился?"), ppText);
            if (vpnUp && tunnelDead) return TunnelDownVerdict();
            var fz = FreezeVerdict(); if (fz != null) return fz;
            var tlf = TunnelLossVerdict(); if (tlf != null) return tlf;
            var rv = ResourceVerdict(); if (rv != null) return rv;
            if (ppProblem) return OwnerVerdict(ppOwner, ppText, Theme.Amber);
            return QualityVerdict();
        }
    }
    class Sanctum
    {
        public string Name = "", Addr = "", Note = "";
        public int Port = 22;
        public string Status; public Color StatusColor = Theme.GreenDim;
        public override string ToString() { return Name + " · " + Addr; }
    }

    class ChronEntry
    {
        public string Id, Sanctum, Headline, Side;
        public int Ritual, Seconds;
        public char Key;
        public DateTime When;
        public double Loss = -2, Ping = -2;
        public Color Color { get { return Key == 'g' ? Theme.Green : Key == 'a' ? Theme.Amber : Theme.Red; } }
    }

    static class Store
    {
        public static readonly string Dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Cogitator");
        static string SettingsFile { get { return Path.Combine(Dir, "settings.ini"); } }
        static string SanctFile { get { return Path.Combine(Dir, "sanctums.tsv"); } }
        public static string ChronDir { get { return Path.Combine(Dir, "chronicle"); } }
        static string ChronIndex { get { return Path.Combine(ChronDir, "index.tsv"); } }

        public static string Pattern = "", Isp = "", Active = "";
        public static bool Guard, Hud;
        public static bool Stealth = true;
        public static string Lang = "";
        public static int HudX = -1, HudY = -1;
        public static int HudOpacity = 90;
        public static bool Glitch = true, Scan = false;
        public static List<Sanctum> Sanctums = new List<Sanctum>();
        public static List<Gate> Gates = new List<Gate>();
        public static List<string> AuspexGates = new List<string>();
        public const int MaxAuspexGates = 4;
        static string GatesFile { get { return Path.Combine(Dir, "gates.tsv"); } }

        public static void SaveGates()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllLines(GatesFile, Gates.Select(x => Esc(x.Name) + "\t" + x.Kind + "\t" + Esc(x.Target) + "\t" + Esc(x.SpeedUrl)).ToArray(), new UTF8Encoding(false));
            }
            catch { }
        }

        static void LoadGates()
        {
            Gates.Clear();
            try
            {
                if (File.Exists(GatesFile))
                {
                    foreach (var line in File.ReadAllLines(GatesFile, Encoding.UTF8))
                    {
                        var p = line.Split(new[] { '\t' });
                        if (p.Length < 3 || p[0].Trim().Length == 0) continue;
                        int k; if (!int.TryParse(p[1], out k) || k < 0 || k > 2) k = 0;
                        Gates.Add(new Gate { Name = p[0], Kind = k, Target = p[2], SpeedUrl = p.Length > 3 ? p[3] : "" });
                    }
                    return;
                }
            }
            catch { }
            foreach (int i in new[] { 0, 3, 4, 10 })
            {
                var pr = GateCheck.Presets[i];
                Gates.Add(new Gate { Name = (string)pr[0], Kind = (int)pr[1], Target = (string)pr[2], SpeedUrl = (string)pr[3] });
            }
            SaveGates();
        }
        public static List<ChronEntry> Chronicle = new List<ChronEntry>();
        const int MaxChron = 300;

        static string Esc(string s) { return (s ?? "").Replace("\t", " ").Replace("\r", " ").Replace("\n", " "); }

        public static string FontChoice = "fixedsys";
        public static void LoadLang()
        {
            try
            {
                if (File.Exists(SettingsFile))
                    foreach (var line in File.ReadAllLines(SettingsFile, Encoding.UTF8))
                        if (line.StartsWith("lang=")) Lang = line.Substring(5).Trim().ToLowerInvariant();
                        else if (line.StartsWith("font=")) FontChoice = line.Substring(5).Trim().ToLowerInvariant();
            }
            catch { }
            if (Lang != "ru" && Lang != "en")
                Lang = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ru" ? "ru" : "en";
            Loc.En = Lang == "en";
        }

        public static void LoadAll()
        {
            string legacyServer = "", legacyPort = "22";
            try
            {
                if (File.Exists(SettingsFile))
                    foreach (var line in File.ReadAllLines(SettingsFile, Encoding.UTF8))
                    {
                        int i = line.IndexOf('='); if (i <= 0) continue;
                        string k = line.Substring(0, i).Trim().ToLowerInvariant(), v = line.Substring(i + 1).Trim();
                        if (k == "server") legacyServer = v;
                        else if (k == "sshport") legacyPort = v;
                        else if (k == "adapter_pattern" && v.Length > 0) Pattern = v == "Amnezia|AmneziaWG|WireGuard|Wintun|awg" ? "" : v;
                        else if (k == "isp" && v.Length > 0 && v != "SkyNet") Isp = v;
                        else if (k == "active") Active = v;
                        else if (k == "guardian") Guard = v == "1";
                        else if (k == "hud") Hud = v == "1";
                        else if (k == "lang") Lang = v;
                        else if (k == "auspex_gate" || k == "auspex_gates") { foreach (var n in v.Split(new char[] { '\t' }).Where(x => x.Length > 0)) if (!AuspexGates.Contains(n)) AuspexGates.Add(n); }
                        else if (k == "hud_x") int.TryParse(v, out HudX);
                        else if (k == "glitch") Glitch = v != "0";
                        else if (k == "scan") Scan = v != "0";
                        else if (k == "hud_opacity") { int o; if (int.TryParse(v, out o)) HudOpacity = Math.Max(25, Math.Min(100, o)); }
                        else if (k == "hud_y") int.TryParse(v, out HudY);
                    }
            }
            catch { }

            Sanctums.Clear();
            try
            {
                if (File.Exists(SanctFile))
                    foreach (var line in File.ReadAllLines(SanctFile, Encoding.UTF8))
                    {
                        var p = line.Split(new[] { '\t' });
                        if (p.Length < 2 || p[1].Trim().Length == 0) continue;
                        int port; if (p.Length < 3 || !int.TryParse(p[2], out port)) port = 22;
                        Sanctums.Add(new Sanctum { Name = p[0], Addr = p[1].Trim(), Port = port, Note = p.Length > 3 ? p[3] : "" });
                    }
            }
            catch { }

            if (Sanctums.Count == 0 && legacyServer.Length > 0)
            {
                int port; if (!int.TryParse(legacyPort, out port)) port = 22;
                Sanctums.Add(new Sanctum { Name = Loc.T("Святилище I"), Addr = legacyServer, Port = port });
                Active = legacyServer;
                SaveSanctums(); SaveSettings();
            }
            if (Active.Length > 0 && !Sanctums.Any(x => x.Addr == Active)) Active = "";
            if (Active.Length == 0 && Sanctums.Count > 0) Active = Sanctums[0].Addr;

            LoadChronicle();
            LoadGates();
            AuspexGates.RemoveAll(n => !Gates.Any(x => x.Name == n));
        }

        public static Sanctum ActiveSanctum { get { return Sanctums.FirstOrDefault(x => x.Addr == Active); } }

        public static void SaveSettings()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllLines(SettingsFile, new[] { "active=" + Active, "adapter_pattern=" + Pattern, "isp=" + Isp, "guardian=" + (Guard ? "1" : "0"), "hud=" + (Hud ? "1" : "0"), "hud_x=" + HudX, "hud_y=" + HudY, "lang=" + Lang, "auspex_gates=" + string.Join("\t", AuspexGates), "hud_opacity=" + HudOpacity, "glitch=" + (Glitch ? "1" : "0"), "scan=" + (Scan ? "1" : "0"), "font=" + Theme.FontKey }, new UTF8Encoding(false));
            }
            catch { }
        }

        public static void SaveSanctums()
        {
            try
            {
                Directory.CreateDirectory(Dir);
                File.WriteAllLines(SanctFile, Sanctums.Select(x => Esc(x.Name) + "\t" + Esc(x.Addr) + "\t" + x.Port + "\t" + Esc(x.Note)).ToArray(), new UTF8Encoding(false));
            }
            catch { }
        }

        static void LoadChronicle()
        {
            Chronicle.Clear();
            try
            {
                if (!File.Exists(ChronIndex)) return;
                foreach (var line in File.ReadAllLines(ChronIndex, Encoding.UTF8))
                {
                    var p = line.Split(new[] { '\t' });
                    if (p.Length < 7) continue;
                    DateTime when;
                    if (!DateTime.TryParseExact(p[0], "yyyyMMdd-HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out when)) continue;
                    int rit, sec; int.TryParse(p[1], out rit); int.TryParse(p[5], out sec);
                    Chronicle.Add(new ChronEntry { Id = p[0], When = when, Ritual = rit, Sanctum = p[2], Headline = p[3], Key = p[4].Length > 0 ? p[4][0] : 'r', Seconds = sec, Side = p[6] });
                }
            }
            catch { }
            Chronicle = Chronicle.OrderByDescending(x => x.When).ToList();
        }

        static void SaveChronIndex()
        {
            try
            {
                Directory.CreateDirectory(ChronDir);
                File.WriteAllLines(ChronIndex, Chronicle.OrderBy(x => x.When).Select(x =>
                    x.Id + "\t" + x.Ritual + "\t" + Esc(x.Sanctum) + "\t" + Esc(x.Headline) + "\t" + x.Key + "\t" + x.Seconds + "\t" + Esc(x.Side)).ToArray(), new UTF8Encoding(false));
            }
            catch { }
        }

        static double Num(string s) { double v; return double.TryParse(s.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out v) ? v : -1; }

        public static void ParseMetrics(ChronEntry e, string text)
        {
            e.Loss = -1; e.Ping = -1;
            if (string.IsNullOrEmpty(text) || e.Ritual == 9) return;
            var m = Regex.Match(text, @"(?:Итог: потери|Result: loss) ([\d\.,]+)%");
            if (!m.Success) m = Regex.Match(text, @"(?:Потери через туннель|Потери напрямую|Loss through the tunnel|Direct loss): ([\d\.,]+)%");
            if (m.Success) e.Loss = Num(m.Groups[1].Value);
            else
            {
                var vals = new List<double>();
                foreach (Match pm in Regex.Matches(text, @"(?:Пинг|Ping) \(([\d\.]+)\): (?:(?:потери|loss) (\d+)%, (?:пинг|ping) ([\d\.,]+) (?:мс|ms)|не отвечает|no reply)"))
                {
                    vals.Add(pm.Groups[2].Success ? Num(pm.Groups[2].Value) : 100);
                    if (pm.Groups[1].Value == "1.1.1.1" && pm.Groups[3].Success) e.Ping = Num(pm.Groups[3].Value);
                }
                if (vals.Count > 0) e.Loss = vals.Average();
            }
            if (e.Ping < 0)
            {
                var pm = Regex.Match(text, @"1\.1\.1\.1 — (\d+) (?:мс|ms)");
                if (pm.Success) e.Ping = Num(pm.Groups[1].Value);
            }
        }

        public static void Metrics(ChronEntry e)
        {
            if (e.Loss > -2) return;
            ParseMetrics(e, e.Ritual == 9 ? "" : ReadReport(e));
        }

        public static void AddChron(ChronEntry e, string report)
        {
            ParseMetrics(e, report);
            try
            {
                Directory.CreateDirectory(ChronDir);
                File.WriteAllText(Path.Combine(ChronDir, e.Id + ".txt"), report, new UTF8Encoding(true));
            }
            catch { }
            Chronicle.Insert(0, e);
            while (Chronicle.Count > MaxChron)
            {
                var old = Chronicle[Chronicle.Count - 1];
                Chronicle.RemoveAt(Chronicle.Count - 1);
                try { File.Delete(Path.Combine(ChronDir, old.Id + ".txt")); } catch { }
            }
            SaveChronIndex();
        }

        public static string ReadReport(ChronEntry e)
        {
            try { return File.ReadAllText(Path.Combine(ChronDir, e.Id + ".txt"), Encoding.UTF8); } catch { return Loc.T("Запись журнала утрачена."); }
        }

        public static void ClearChron()
        {
            try { foreach (var f in Directory.GetFiles(ChronDir, "*.txt")) File.Delete(f); } catch { }
            Chronicle.Clear();
            SaveChronIndex();
        }
    }

    static class Autostart
    {
        const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run", Name = "Cogitator";
        static string Command { get { return "\"" + Application.ExecutablePath + "\" --tray"; } }

        public static bool IsOn
        {
            get
            {
                try { using (var k = Registry.CurrentUser.OpenSubKey(RunKey)) return k != null && k.GetValue(Name) != null; }
                catch { return false; }
            }
        }

        public static string Set(bool on)
        {
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(RunKey))
                {
                    if (on) k.SetValue(Name, Command);
                    else k.DeleteValue(Name, false);
                }
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        public static void Refresh()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(RunKey, true))
                {
                    var v = k == null ? null : k.GetValue(Name) as string;
                    if (v != null && v != Command) k.SetValue(Name, Command);
                }
            }
            catch { }
        }
    }

    class GuardResult { public bool Ok, VpnUp; public string VpnName, Via; public long Ms; }

    static class Guardian
    {
        public static GuardResult Check(string pattern)
        {
            var r = new GuardResult();
            try
            {
                var vpn = Tun.Find(pattern);
                r.VpnUp = vpn != null;
                r.VpnName = vpn != null ? vpn.Name : null;
            }
            catch { }
            using (var p = new Ping())
                foreach (var t in new[] { "1.1.1.1", "8.8.8.8", "77.88.8.8" })
                {
                    try
                    {
                        var rep = p.Send(t, 1500);
                        if (rep.Status == IPStatus.Success) { r.Ok = true; r.Ms = rep.RoundtripTime; r.Via = "ping " + t; return r; }
                    }
                    catch { }
                }
            long ms; string b;
            if (Diag.HttpOk("https://www.gstatic.com/generate_204", 4000, false, out ms, out b)) { r.Ok = true; r.Ms = ms; r.Via = "https"; }
            return r;
        }

        public static string Fmt(TimeSpan t)
        {
            if (t.TotalSeconds < 60) return (int)t.TotalSeconds + Loc.T(" с");
            if (t.TotalMinutes < 60) return (int)t.TotalMinutes + Loc.T(" мин ") + t.Seconds + Loc.T(" с");
            return (int)t.TotalHours + Loc.T(" ч ") + t.Minutes + Loc.T(" мин");
        }
    }
    static class AutoDetect
    {
        public class Found { public string Host, Name, Source; public int Port = 22; }

        static readonly Regex EndpointRx = new Regex(@"Endpoint\s*=\s*\[?([A-Za-z0-9\.\-]+)\]?\s*:\s*(\d{2,5})", RegexOptions.IgnoreCase);
        static readonly Regex ObjRx = new Regex("\\{[^{}]*\"hostName\"[^{}]*\\}", RegexOptions.Singleline);
        static readonly Regex HostRx = new Regex("\"hostName\"\\s*:\\s*\"([^\"]+)\"");
        static readonly Regex PortRx = new Regex("\"port\"\\s*:\\s*\"?(\\d{1,5})");
        static readonly Regex DescRx = new Regex("\"description\"\\s*:\\s*\"([^\"]*)\"");
        static readonly Regex PathRx = new Regex(@"[A-Za-z]:\\[^""<>|*?\r\n]+?\.(conf|json)", RegexOptions.IgnoreCase);
        const string PrivateRx = @"^(10\.|127\.|0\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.)";

        public static List<Found> Run(List<string> log)
        {
            var found = new List<Found>();
            int files = 0, values = 0, services = 0;

            try
            {
                using (var svcs = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                    if (svcs != null)
                        foreach (var name in svcs.GetSubKeyNames())
                        {
                            bool tunnel = name.StartsWith("WireGuardTunnel$", StringComparison.OrdinalIgnoreCase) || name.StartsWith("AmneziaWGTunnel$", StringComparison.OrdinalIgnoreCase);
                            if (!tunnel && name.IndexOf("amnezia", StringComparison.OrdinalIgnoreCase) < 0) continue;
                            services++;
                            string tname = name.Contains("$") ? name.Substring(name.IndexOf('$') + 1) : name;
                            using (var k = svcs.OpenSubKey(name))
                            {
                                var img = k == null ? null : k.GetValue("ImagePath") as string;
                                if (img == null) continue;
                                foreach (Match m in PathRx.Matches(img)) ScanFile(m.Value, Loc.T("служба ") + name, tname, found, ref files);
                            }
                        }
            }
            catch { }
            log.Add(Loc.T("службы туннелей: ") + services);

            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            };
            foreach (var root in roots.Where(x => !string.IsNullOrEmpty(x)).Distinct())
            {
                try
                {
                    foreach (var dir in Directory.GetDirectories(root))
                    {
                        var dn = Path.GetFileName(dir);
                        if (dn.IndexOf("amnezia", StringComparison.OrdinalIgnoreCase) < 0 && dn.IndexOf("wireguard", StringComparison.OrdinalIgnoreCase) < 0) continue;
                        Walk(dir, 0, found, ref files);
                    }
                }
                catch { }
            }
            log.Add(Loc.T("просмотрено файлов: ") + files);

            try
            {
                using (var sw = Registry.CurrentUser.OpenSubKey("Software"))
                    if (sw != null)
                        foreach (var name in sw.GetSubKeyNames())
                            if (name.IndexOf("amnezia", StringComparison.OrdinalIgnoreCase) >= 0)
                                using (var k = sw.OpenSubKey(name)) ScanKey(k, 0, Loc.T("реестр ") + name, found, ref values);
            }
            catch { }
            log.Add(Loc.T("значений в реестре: ") + values);
            return found;
        }

        static void Walk(string dir, int depth, List<Found> found, ref int files)
        {
            if (depth > 5 || files > 400) return;
            try
            {
                foreach (var f in Directory.GetFiles(dir))
                {
                    var ext = Path.GetExtension(f).ToLowerInvariant();
                    if (ext != ".conf" && ext != ".json" && ext != ".ini" && ext != ".cfg" && ext != ".txt") continue;
                    ScanFile(f, Loc.T("файл ") + f, null, found, ref files);
                    if (files > 400) return;
                }
                foreach (var d in Directory.GetDirectories(dir)) Walk(d, depth + 1, found, ref files);
            }
            catch { }
        }

        static void ScanFile(string path, string source, string tunnelName, List<Found> found, ref int files)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists || fi.Length > 1024 * 1024) return;
                files++;
                ScanText(File.ReadAllText(path), source, tunnelName, found);
            }
            catch { }
        }

        static void ScanKey(RegistryKey k, int depth, string source, List<Found> found, ref int values)
        {
            if (k == null || depth > 4 || values > 3000) return;
            try
            {
                foreach (var vn in k.GetValueNames())
                {
                    values++;
                    var v = k.GetValue(vn);
                    var str = v as string;
                    var arr = v as string[];
                    var bin = v as byte[];
                    if (str != null) ScanText(str, source, null, found);
                    else if (arr != null) ScanText(string.Join("\n", arr), source, null, found);
                    else if (bin != null)
                    {
                        ScanText(Encoding.UTF8.GetString(bin), source, null, found);
                        ScanText(Encoding.Unicode.GetString(bin), source, null, found);
                    }
                }
                foreach (var sk in k.GetSubKeyNames())
                    using (var c = k.OpenSubKey(sk)) ScanKey(c, depth + 1, source, found, ref values);
            }
            catch { }
        }

        static void ScanText(string text, string source, string tunnelName, List<Found> found)
        {
            if (string.IsNullOrEmpty(text)) return;
            text = text.Replace("\\\"", "\"");
            foreach (Match m in EndpointRx.Matches(text))
                Add(found, m.Groups[1].Value, 22, tunnelName, source);
            foreach (Match o in ObjRx.Matches(text))
            {
                var h = HostRx.Match(o.Value);
                if (!h.Success) continue;
                int port = 22;
                var pm = PortRx.Match(o.Value);
                if (pm.Success) { int pp; if (int.TryParse(pm.Groups[1].Value, out pp) && pp > 0 && pp < 65536) port = pp; }
                var dm = DescRx.Match(o.Value);
                Add(found, h.Groups[1].Value, port, dm.Success && dm.Groups[1].Value.Trim().Length > 0 ? dm.Groups[1].Value.Trim() : tunnelName, source);
            }
        }

        static void Add(List<Found> found, string host, int port, string name, string source)
        {
            host = (host ?? "").Trim().Trim('[', ']');
            if (host.Length < 4 || host.Length > 253 || !host.Contains(".")) return;
            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(host, PrivateRx)) return;
            if (!Regex.IsMatch(host, @"^[A-Za-z0-9\.\-]+$")) return;
            var ex = found.FirstOrDefault(f => f.Host.Equals(host, StringComparison.OrdinalIgnoreCase));
            if (ex != null)
            {
                if ((ex.Name == null || ex.Name.Length == 0) && !string.IsNullOrEmpty(name)) ex.Name = name;
                if (ex.Port == 22 && port != 22) ex.Port = port;
                return;
            }
            found.Add(new Found { Host = host, Port = port, Name = name, Source = source });
        }
    }
    static class SysMon
    {
        [StructLayout(LayoutKind.Sequential)] struct FILETIME { public uint Lo, Hi; }
        [StructLayout(LayoutKind.Sequential)] class MEMSTAT { public uint Len = 64, Load; public ulong TotalPhys, AvailPhys, TotalPage, AvailPage, TotalVirt, AvailVirt, AvailExt; }
        [DllImport("kernel32.dll")] static extern bool GetSystemTimes(out FILETIME idle, out FILETIME kernel, out FILETIME user);
        [DllImport("kernel32.dll")] static extern bool GlobalMemoryStatusEx([In, Out] MEMSTAT m);

        public static volatile float Cpu = -1, Ram = -1, Gpu = -1;
        public static double RamUsedGb, RamTotalGb;
        static Thread th;
        static ulong pIdle, pTotal;
        static Dictionary<string, CounterSample> prevGpu;
        static bool gpuDead;

        public static void Start()
        {
            if (th != null) return;
            th = new Thread(() =>
            {
                while (true)
                {
                    try { Sample(); } catch { }
                    Thread.Sleep(1500);
                }
            }) { IsBackground = true, Priority = ThreadPriority.BelowNormal };
            th.Start();
        }

        static ulong U(FILETIME f) { return ((ulong)f.Hi << 32) | f.Lo; }

        static void Sample()
        {
            FILETIME i, k, u;
            if (GetSystemTimes(out i, out k, out u))
            {
                ulong idle = U(i), total = U(k) + U(u);
                if (pTotal > 0 && total > pTotal) Cpu = (float)(100.0 * (1 - (double)(idle - pIdle) / (total - pTotal)));
                pIdle = idle; pTotal = total;
            }
            var m = new MEMSTAT();
            if (GlobalMemoryStatusEx(m))
            {
                RamTotalGb = m.TotalPhys / 1073741824.0; RamUsedGb = (m.TotalPhys - m.AvailPhys) / 1073741824.0;
                Ram = (float)(100.0 * (m.TotalPhys - m.AvailPhys) / Math.Max(1, m.TotalPhys));
            }
            if (!gpuDead) SampleGpu();
        }

        static void SampleGpu()
        {
            try
            {
                var cat = new PerformanceCounterCategory("GPU Engine");
                var all = cat.ReadCategory();
                InstanceDataCollection col = null;
                foreach (DictionaryEntry de in all)
                {
                    string key = ((string)de.Key).ToLowerInvariant();
                    if (key.Contains("utiliz") || key.Contains("использ")) { col = (InstanceDataCollection)de.Value; break; }
                }
                if (col == null) { gpuDead = true; return; }
                var cur = new Dictionary<string, CounterSample>();
                foreach (InstanceData d in col.Values) cur[d.InstanceName] = d.Sample;
                if (prevGpu != null)
                {
                    var eng = new Dictionary<string, double>();
                    foreach (var kv in cur)
                    {
                        CounterSample old;
                        if (!prevGpu.TryGetValue(kv.Key, out old)) continue;
                        int e = kv.Key.IndexOf("_luid_");
                        string engine = e >= 0 ? kv.Key.Substring(e) : kv.Key;
                        double v = CounterSample.Calculate(old, kv.Value);
                        if (double.IsNaN(v) || v < 0) continue;
                        double acc; eng.TryGetValue(engine, out acc); eng[engine] = acc + v;
                    }
                    Gpu = eng.Count > 0 ? (float)Math.Min(100, eng.Values.Max()) : 0;
                }
                prevGpu = cur;
            }
            catch { gpuDead = true; }
        }
    }
    class SonarHop { public int Ttl; public string Addr, Asn, AsName; public List<double> Hist = new List<double>(); }
    static class SonarProbe
    {
        public static readonly object Lk = new object();
        public static List<SonarHop> Hops = new List<SonarHop>();
        public static int Reach = -1;
        public static DateTime Last = DateTime.MinValue;
        public static bool Tunnel;
        public static volatile bool Want;
        static Thread th;
        public const string Target = "1.1.1.1";

        public static void Start()
        {
            if (th != null) return;
            th = new Thread(() =>
            {
                while (true)
                {
                    try { if (Want && (DateTime.Now - Last).TotalSeconds >= 25) Sweep(); } catch { }
                    Thread.Sleep(1000);
                }
            }) { IsBackground = true, Priority = ThreadPriority.BelowNormal };
            th.Start();
        }

        static void Sweep()
        {
            Tunnel = Tun.Find(Store.Pattern) != null;
            int maxTtl = Reach > 0 ? Math.Min(16, Reach) : 16;
            var buf = new byte[32];
            int reached = -1, silentRun = 0;
            using (var p = new Ping())
                for (int ttl = 1; ttl <= maxTtl; ttl++)
                {
                    string addr = null; double rtt = -1;
                    var sw = Stopwatch.StartNew();
                    try
                    {
                        var r = p.Send(Target, 800, buf, new PingOptions(ttl, true));
                        if (r.Status == IPStatus.Success || r.Status == IPStatus.TtlExpired || r.Status == IPStatus.TimeExceeded)
                        { addr = r.Address != null ? r.Address.ToString() : null; rtt = r.Status == IPStatus.Success && r.RoundtripTime > 0 ? r.RoundtripTime : sw.ElapsedMilliseconds; }
                        if (r.Status == IPStatus.Success) reached = ttl;
                    }
                    catch { }
                    lock (Lk)
                    {
                        while (Hops.Count < ttl) Hops.Add(new SonarHop { Ttl = Hops.Count + 1 });
                        var h = Hops[ttl - 1];
                        if (addr != null && addr != h.Addr) { h.Addr = addr; h.Asn = Diag.AsnOf(addr); h.AsName = Diag.AsName(h.Asn); }
                        h.Hist.Add(rtt); if (h.Hist.Count > 8) h.Hist.RemoveAt(0);
                    }
                    if (reached > 0) break;
                    silentRun = addr == null ? silentRun + 1 : 0;
                    if (Reach < 0 && silentRun >= 4 && ttl > 6) break;
                }
            lock (Lk)
            {
                if (reached > 0) { Reach = reached; if (Hops.Count > reached) Hops.RemoveRange(reached, Hops.Count - reached); }
                else Reach = -1;
            }
            Last = DateTime.Now;
        }
    }
    static class Tun
    {
        [DllImport("iphlpapi.dll")] static extern int GetBestInterface(uint dwDestAddr, out uint idx);

        public const string Known = @"amnezia|wireguard|wintun|\bawg|\btun\d*\b|-tun\b|\btun-|tap-windows|openvpn|sing-?box|throne|nekoray|nekobox|hiddify|v2ray|xray|clash|mihomo|outline|warp|psiphon|proton|nordlynx|mullvad";
        const string NotTunnel = @"tailscale|zerotier|hyper-v|vethernet|virtualbox|vmware|wsl|docker|npcap|bluetooth|teredo|isatap|6to4|loopback|kernel debug";

        public static bool Looks(NetworkInterface n, string pattern)
        {
            string id = n.Name + " " + n.Description;
            try
            {
                if (Regex.IsMatch(id, NotTunnel, RegexOptions.IgnoreCase)) return false;
                if (!string.IsNullOrEmpty(pattern) && Regex.IsMatch(id, pattern, RegexOptions.IgnoreCase)) return true;
                return Regex.IsMatch(id, Known, RegexOptions.IgnoreCase);
            }
            catch { return false; }
        }

        static int Idx(NetworkInterface n) { try { return n.GetIPProperties().GetIPv4Properties().Index; } catch { return -1; } }

        public static NetworkInterface Find(string pattern) { NetworkInterface any; return Find(pattern, out any); }

        public static NetworkInterface Find(string pattern, out NetworkInterface anyKnown)
        {
            anyKnown = null;
            NetworkInterface[] all;
            try { all = NetworkInterface.GetAllNetworkInterfaces(); } catch { return null; }
            int best = -1;
            try { uint bi; if (GetBestInterface(BitConverter.ToUInt32(IPAddress.Parse("1.1.1.1").GetAddressBytes(), 0), out bi) == 0) best = (int)bi; } catch { }
            NetworkInterface up = null;
            foreach (var n in all)
            {
                if (n.NetworkInterfaceType == NetworkInterfaceType.Loopback || !Looks(n, pattern)) continue;
                if (anyKnown == null) anyKnown = n;
                if (n.OperationalStatus != OperationalStatus.Up) continue;
                if (up == null || Idx(n) == best) up = n;
            }
            if (up != null) return up;
            var bn = all.FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up && Idx(n) == best);
            if (bn != null && bn.NetworkInterfaceType != NetworkInterfaceType.Loopback && !Regex.IsMatch(bn.Name + " " + bn.Description, NotTunnel, RegexOptions.IgnoreCase))
            {
                byte[] mac = null;
                try { mac = bn.GetPhysicalAddress().GetAddressBytes(); } catch { }
                bool pppoe = Regex.IsMatch(bn.Name + " " + bn.Description, @"pppoe|высокоскоростн|broadband|широкополос", RegexOptions.IgnoreCase);
                if (!pppoe && (mac == null || mac.Length == 0 || mac.All(x => x == 0) || bn.NetworkInterfaceType == NetworkInterfaceType.Ppp || bn.NetworkInterfaceType == NetworkInterfaceType.Tunnel))
                    return bn;
            }
            return null;
        }

        public static string SystemProxy()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
                {
                    if (k == null) return null;
                    var en = k.GetValue("ProxyEnable");
                    if (en == null || Convert.ToInt32(en) == 0) return null;
                    string srv = (k.GetValue("ProxyServer") as string ?? "").Trim();
                    if (srv.Length == 0) return null;
                    var m = Regex.Match(srv, @"(?:^|[;=])((?:127\.\d+\.\d+\.\d+|localhost|\[::1\]):\d+)", RegexOptions.IgnoreCase);
                    return m.Success ? m.Groups[1].Value : null;
                }
            }
            catch { return null; }
        }
    }

    class AxMin { public DateTime When; public int Sent, Recv; public double Avg, Max, Jit; public int Mode; }

    static class AuspexLog
    {
        static string DirA { get { return Path.Combine(Store.Dir, "auspex"); } }
        static readonly object sync = new object();
        static DateTime cur = DateTime.MinValue;
        static int sent, recv, mode; static double sum, max, jit, prev = -1;
        static bool cleaned;

        public static void Add(double v, int m)
        {
            lock (sync)
            {
                var now = DateTime.Now; var minute = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0);
                if (minute != cur) { FlushLocked(); cur = minute; sent = recv = 0; sum = max = jit = 0; }
                sent++; mode = m;
                if (v >= 0)
                {
                    recv++; sum += v; if (v > max) max = v;
                    if (prev >= 0) jit += Math.Abs(v - prev);
                }
                prev = v;
            }
        }

        public static void Flush() { lock (sync) { FlushLocked(); sent = 0; } }

        static void FlushLocked()
        {
            if (sent < 5 || cur == DateTime.MinValue) return;
            try
            {
                Directory.CreateDirectory(DirA);
                string line = cur.ToString("yyyyMMdd HHmm", CultureInfo.InvariantCulture) + "\t" + sent + "\t" + recv + "\t" +
                    (recv > 0 ? (sum / recv).ToString("0.#", CultureInfo.InvariantCulture) : "-1") + "\t" + max.ToString("0", CultureInfo.InvariantCulture) + "\t" +
                    (recv > 1 ? (jit / Math.Max(1, recv - 1)).ToString("0.#", CultureInfo.InvariantCulture) : "0") + "\t" + mode;
                File.AppendAllText(Path.Combine(DirA, cur.ToString("yyyyMMdd") + ".tsv"), line + "\n");
                if (!cleaned)
                {
                    cleaned = true;
                    foreach (var f in Directory.GetFiles(DirA, "*.tsv"))
                    {
                        DateTime d;
                        if (DateTime.TryParseExact(Path.GetFileNameWithoutExtension(f), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out d) && (DateTime.Today - d).TotalDays > 90)
                            try { File.Delete(f); } catch { }
                    }
                }
            }
            catch { }
        }

        public static List<AxMin> Load(DateTime from, DateTime to)
        {
            var res = new List<AxMin>();
            try
            {
                if (!Directory.Exists(DirA)) return res;
                foreach (var f in Directory.GetFiles(DirA, "*.tsv").OrderBy(x => x))
                {
                    DateTime d;
                    if (!DateTime.TryParseExact(Path.GetFileNameWithoutExtension(f), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out d)) continue;
                    if (d < from.Date || d > to.Date) continue;
                    foreach (var line in File.ReadAllLines(f))
                    {
                        var c = line.Split(new[] { '\t' }); if (c.Length < 7) continue;
                        DateTime w;
                        if (!DateTime.TryParseExact(c[0], "yyyyMMdd HHmm", CultureInfo.InvariantCulture, DateTimeStyles.None, out w)) continue;
                        if (w < from || w > to) continue;
                        var m = new AxMin { When = w };
                        int.TryParse(c[1], out m.Sent); int.TryParse(c[2], out m.Recv);
                        double.TryParse(c[3], NumberStyles.Float, CultureInfo.InvariantCulture, out m.Avg);
                        double.TryParse(c[4], NumberStyles.Float, CultureInfo.InvariantCulture, out m.Max);
                        double.TryParse(c[5], NumberStyles.Float, CultureInfo.InvariantCulture, out m.Jit);
                        int.TryParse(c[6], out m.Mode);
                        if (m.Sent > 0) res.Add(m);
                    }
                }
            }
            catch { }
            return res;
        }
    }

    class Drop
    {
        public DateTime Start;
        public int DurSec, GapSec, Probed;
        public bool ServerUp, SshUp;
    }

    static class DropLog
    {
        static string FileP { get { return Path.Combine(Store.Dir, "drops.tsv"); } }
        static readonly object sync = new object();
        static DateTime lastStart = DateTime.MinValue;

        public static Drop Begin(DateTime start)
        {
            var d = new Drop { Start = start };
            lock (sync)
            {
                if (lastStart != DateTime.MinValue)
                {
                    int g = (int)(start - lastStart).TotalSeconds;
                    if (g > 0 && g < 86400) d.GapSec = g;
                }
                lastStart = start;
            }
            return d;
        }

        public static void Probe(Drop d)
        {
            if (Store.Stealth) { d.Probed = 0; return; }
            try
            {
                var s = Store.ActiveSanctum;
                if (s == null || string.IsNullOrEmpty(s.Addr)) { d.Probed = -1; return; }
                string ip = Diag.ResolveIp(s.Addr);
                if (ip == null) { d.Probed = -1; return; }
                bool ping = false;
                try { using (var p = new Ping()) { var r = p.Send(ip, 2000); ping = r.Status == IPStatus.Success; } } catch { }
                bool ssh = Diag.TcpOk(ip, s.Port, 2500);
                bool https = Diag.TcpOk(ip, 443, 2500);
                d.SshUp = ssh;
                d.ServerUp = ping || ssh || https;
                d.Probed = 1;
            }
            catch { d.Probed = 1; }
        }

        public static void End(Drop d, DateTime end)
        {
            d.DurSec = Math.Max(1, (int)(end - d.Start).TotalSeconds);
            try
            {
                Directory.CreateDirectory(Store.Dir);
                string line = d.Start.ToString("yyyyMMdd HHmmss", CultureInfo.InvariantCulture) + "\t" + d.DurSec + "\t" +
                    d.Probed + "\t" + (d.ServerUp ? 1 : 0) + "\t" + (d.SshUp ? 1 : 0) + "\t" + d.GapSec;
                lock (sync) File.AppendAllText(FileP, line + "\n");
            }
            catch { }
        }

        public static List<Drop> Load(DateTime from, DateTime to)
        {
            var res = new List<Drop>();
            try
            {
                if (!File.Exists(FileP)) return res;
                string[] lines; lock (sync) lines = File.ReadAllLines(FileP);
                foreach (var ln in lines)
                {
                    var c = ln.Split(new[] { '\t' }); if (c.Length < 6) continue;
                    DateTime w;
                    if (!DateTime.TryParseExact(c[0], "yyyyMMdd HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out w)) continue;
                    if (w < from || w > to) continue;
                    var d = new Drop { Start = w };
                    int.TryParse(c[1], out d.DurSec);
                    int.TryParse(c[2], out d.Probed);
                    int su; int.TryParse(c[3], out su); d.ServerUp = su == 1;
                    int sh; int.TryParse(c[4], out sh); d.SshUp = sh == 1;
                    int.TryParse(c[5], out d.GapSec);
                    res.Add(d);
                }
            }
            catch { }
            return res;
        }
    }
    class AuspexData

    {
        public double Last = -2;
        public double Loss, Jitter;
        public int MissStreak;
        public volatile bool Vpn, Proxy;
        public DateTime At = DateTime.MinValue;
        public bool Stale { get { return Last != -2 && At != DateTime.MinValue && (DateTime.Now - At).TotalSeconds > 3; } }
        public bool Dead { get { return MissStreak >= 2 || Stale; } }
        public List<double> Hist = new List<double>();
        public Color State
        {
            get
            {
                if (Last == -2) return Theme.GreenDim;
                if (Dead) return Theme.Red;
                if (Loss >= 3 || Last > 250) return Theme.Red;
                if (Loss > 0 || Last > 120 || Jitter > 30) return Theme.Amber;
                return Theme.Green;
            }
        }
    }
    class Gate
    {
        public string Name = "", Target = "", SpeedUrl = "";
        public int Kind;
        public string Status, Detail;
        public char Key = ' ';
        public DateTime At;
        public Color StatusColor { get { return Key == 'g' ? Theme.Green : Key == 'a' ? Theme.Amber : Key == 'r' ? Theme.Red : Theme.GreenDim; } }
        public static readonly string[] Kinds = { "HTTPS", "TCP", "PING" };
    }

    class GateResult { public char Key; public string Status, Detail, LogLine; }

    static class GateCheck
    {
        [DllImport("iphlpapi.dll")] static extern int GetBestInterface(uint dwDestAddr, out uint idx);

        public static readonly object[][] Presets =
        {
            new object[] { "Discord", 0, "https://discord.com/api/v10/gateway", "" },
            new object[] { "Discord CDN", 0, "https://cdn.discordapp.com", "" },
            new object[] { "YouTube", 0, "https://www.youtube.com/generate_204", "" },
            new object[] { "YouTube · " + Loc.T("видеосерверы"), 0, "https://redirector.googlevideo.com/report_mapping", "" },
            new object[] { "Telegram", 0, "https://api.telegram.org", "" },
            new object[] { "Telegram DC", 1, "149.154.167.51:443", "" },
            new object[] { "Twitch", 0, "https://www.twitch.tv", "" },
            new object[] { "Steam", 0, "https://store.steampowered.com", "" },
            new object[] { "WhatsApp", 0, "https://web.whatsapp.com", "" },
            new object[] { "ChatGPT", 0, "https://chatgpt.com", "" },
            new object[] { "Cloudflare · " + Loc.T("контроль"), 0, "https://www.cloudflare.com/cdn-cgi/trace", "https://speed.cloudflare.com/__down?bytes=2500000" }
        };

        public static void Split(Gate g, out string host, out int port)
        {
            string t = (g.Target ?? "").Trim();
            host = t; port = 443;
            try
            {
                if (t.Contains("://"))
                {
                    var u = new Uri(t);
                    host = u.Host; port = u.IsDefaultPort ? (u.Scheme == "http" ? 80 : 443) : u.Port;
                    return;
                }
                int slash = t.IndexOf('/'); if (slash >= 0) t = t.Substring(0, slash);
                int c = t.LastIndexOf(':'); int p;
                if (c > 0 && t.IndexOf(':') == c && int.TryParse(t.Substring(c + 1), out p) && p > 0 && p < 65536) { host = t.Substring(0, c); port = p; }
                else host = t;
            }
            catch { }
        }

        public static string HostOf(Gate g) { string h; int p; Split(g, out h, out p); return h; }

        public static string Convert(string target, int kind)
        {
            string h; int p;
            Split(new Gate { Target = target }, out h, out p);
            if (string.IsNullOrEmpty(h)) return target;
            if (kind == 0) return "https://" + h + (p != 443 ? ":" + p : "");
            if (kind == 1) return h + ":" + p;
            return h;
        }

        public static string Resolve(string h)
        {
            if (string.IsNullOrEmpty(h)) return null;
            IPAddress a;
            if (IPAddress.TryParse(h, out a)) return a.ToString();
            try
            {
                var t = Task.Run(() => Dns.GetHostAddresses(h));
                if (!t.Wait(4000)) return null;
                var ip = t.Result.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
                return ip == null ? null : ip.ToString();
            }
            catch { return null; }
        }

        public static string Route(string ip, string pattern)
        {
            if (ip == null) return null;
            try
            {
                var vpn = Tun.Find(pattern);
                if (vpn == null) return Tun.SystemProxy() != null ? Loc.T("напрямую (клиент в режиме прокси — туннеля нет)") : Loc.T("напрямую (VPN выключен)");
                int vIdx = vpn.GetIPProperties().GetIPv4Properties().Index;
                uint idx;
                if (GetBestInterface(BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes(), 0), out idx) == 0)
                    return (int)idx == vIdx ? Loc.T("через туннель") : Loc.T("мимо туннеля");
            }
            catch { }
            return null;
        }

        static readonly string TlsCut = Loc.T("обрыв на рукопожатии TLS — так выглядит блокировка по имени сервиса (SNI)");

        public static double Probe(Gate g, string ip, int timeout, out string why, out double tlsMs, out bool certBad)
        {
            why = null; tlsMs = -1; certBad = false;
            string host; int port;
            Split(g, out host, out port);
            try
            {
                if (g.Kind == 2)
                {
                    using (var p = new Ping())
                    {
                        var r = p.Send(ip ?? host, timeout);
                        if (r.Status == IPStatus.Success) return r.RoundtripTime;
                        why = Loc.T("нет ответа на ping (многие сервисы его не пропускают — тогда лучше TCP)");
                        return -1;
                    }
                }
                if (ip == null) { why = Loc.T("имя не разрешается (DNS)"); return -1; }
                var c = new TcpClient();
                try
                {
                    var sw = Stopwatch.StartNew();
                    var ar = c.BeginConnect(ip, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeout)) { why = Loc.T("тишина: соединение не установлено (таймаут)"); return -1; }
                    c.EndConnect(ar);
                    double rtt = sw.ElapsedMilliseconds;
                    if (g.Kind == 1) return rtt;

                    bool bad = false;
                    var ssl = new SslStream(c.GetStream(), false, (s, cert, chain, err) => { bad = err != SslPolicyErrors.None; return true; });
                    var sw2 = Stopwatch.StartNew();
                    var ar2 = ssl.BeginAuthenticateAsClient(host, null, (SslProtocols)(3072 | 768), false, null, null);
                    if (!ar2.AsyncWaitHandle.WaitOne(timeout)) { why = TlsCut; return -1; }
                    try { ssl.EndAuthenticateAsClient(ar2); }
                    catch { why = TlsCut; return -1; }
                    tlsMs = sw2.ElapsedMilliseconds;
                    certBad = bad;
                    try { ssl.Dispose(); } catch { }
                    return rtt;
                }
                finally { try { c.Close(); } catch { } }
            }
            catch (SocketException) { why = Loc.T("соединение отвергнуто"); return -1; }
            catch (PingException) { why = Loc.T("имя не разрешается (DNS)"); return -1; }
            catch (Exception ex) { why = ex.Message; return -1; }
        }

        static double Speed(string url, out string note)
        {
            note = null;
            long bytes = 0; bool started = false;
            var sw = Stopwatch.StartNew();
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = 8000; req.ReadWriteTimeout = 5000; req.UserAgent = "Mozilla/5.0 Cogitator/1.0";
                using (var resp = req.GetResponse())
                using (var st = resp.GetResponseStream())
                {
                    started = true;
                    var buf = new byte[65536];
                    while (bytes < 2500000 && sw.Elapsed.TotalSeconds < 5)
                    {
                        int n = st.Read(buf, 0, buf.Length);
                        if (n <= 0) break;
                        bytes += n;
                    }
                }
            }
            catch { }
            double secs = Math.Max(0.001, sw.Elapsed.TotalSeconds);
            if (started && bytes < 128 * 1024) { note = Loc.T("поток замер после ") + (bytes / 1024) + Loc.T(" КБ"); return 0; }
            if (bytes < 64 * 1024) { note = Loc.T("замер скорости не удался"); return -1; }
            return Math.Round(bytes * 8 / secs / 1000000, 1);
        }

        public static GateResult Run(Gate g, string pattern, bool speedViaTunnel = false)
        {
            var res = new GateResult();
            string ip = Resolve(HostOf(g));
            string route = Route(ip, pattern);
            var times = new List<double>(); var tls = new List<double>(); string why = null; bool certBad = false;
            int tries = g.Kind == 2 ? 10 : 3;
            for (int i = 0; i < tries; i++)
            {
                string w; double t; bool cb;
                double ms = Probe(g, ip, g.Kind == 2 ? 1000 : 5000, out w, out t, out cb);
                if (ms >= 0) { times.Add(ms); if (t >= 0) tls.Add(t); if (cb) certBad = true; } else why = w;
                if (i == 0 && ms < 0 && g.Kind != 2 && ip == null) { tries = 1; break; }
                if (g.Kind == 2) Thread.Sleep(150);
            }
            int ok = times.Count, sent = tries;
            double avg = ok > 0 ? Math.Round(times.Average()) : -1;
            var parts = new List<string>();
            if (ok > 0) parts.Add(avg + Loc.T(" мс"));
            if (tls.Count > 0) parts.Add("TLS " + Math.Round(tls.Average()) + Loc.T(" мс"));
            if (g.Kind == 2) parts.Add(Loc.T("потери ") + Math.Round(100.0 * (sent - ok) / sent) + "%");
            else if (ok < sent && ok > 0) parts.Add(ok + "/" + sent + Loc.T(" попыток"));
            if (route != null) parts.Add(route);
            if (certBad) parts.Add(Loc.T("сертификат не прошёл проверку — возможна подмена трафика"));
            double speed = -1; string snote = null;
            bool tunnelRoute = route == Loc.T("через туннель");
            if (ok > 0 && !string.IsNullOrEmpty(g.SpeedUrl) && tunnelRoute && !speedViaTunnel) parts.Add(Loc.T("скорость через туннель меряется только при проверке выбранных врат"));
            else if (ok > 0 && !string.IsNullOrEmpty(g.SpeedUrl)) { speed = Speed(g.SpeedUrl, out snote); if (speed >= 0) parts.Add(speed + Loc.T(" Мбит/с")); if (snote != null) parts.Add(snote); }

            if (ok == 0)
            {
                res.Key = 'r'; res.Status = Loc.T("ЗАПЕЧАТАНЫ");
                if (why != null) parts.Insert(0, why);
            }
            else if (ok < sent || avg > 500 || (speed >= 0 && speed < 2) || snote != null || certBad)
            {
                res.Key = 'a'; res.Status = Loc.T("СКРИПЯТ");
                if (why != null && ok < sent) parts.Add(why);
            }
            else { res.Key = 'g'; res.Status = Loc.T("ОТКРЫТЫ"); }
            res.Detail = string.Join(" · ", parts);
            string tag = res.Key == 'g' ? Loc.T("[ ЧИСТО  ] ") : res.Key == 'a' ? Loc.T("[ТРЕВОГА ] ") : Loc.T("[ ЕРЕСЬ  ] ");
            res.LogLine = tag + g.Name + " (" + Gate.Kinds[g.Kind] + " " + g.Target + ") — " + res.Status + (res.Detail.Length > 0 ? " · " + res.Detail : "");
            return res;
        }
    }
    class GateLive
    {
        public string Name;
        public double Last = -2;
        public string Why;
        public List<double> Hist = new List<double>();
    }
}
