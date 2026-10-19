# Vox Cogitator · Когитатор Связи

Network & VPN diagnostics for Windows, wrapped in the soul of an old CRT terminal.
Диагностика сети и VPN для Windows в духе старого ЭЛТ-терминала.

![Terminal](docs/home.png)

## Русский

Когитатор отвечает на вопрос «кто виноват»: твоя сеть, провайдер, VPN-сервер или путь до него.

- **Святилища** — реестр твоих VPN-серверов; одно избирается активным.
- **Ритуалы испытаний**
  - **I · Малая литания** — роутер, интернет, DNS: чья вина — дома или у провайдера.
  - **II · Вопрошание духа VPN** — жив ли туннель и сервер, распознаёт kill switch.
  - **III · Путь через варп** — трассировка мимо туннеля и через него, владельцы узлов по ASN, карта пути.
  - **IV · Великий ритуал** — всё сразу, MTU и окончательный приговор.
  - **V · Перекличка пакетов** — есть ли потери прямо сейчас.
- **Сонар** — фоновая трассировка до 1.1.1.1: прыжки, задержки, потери, узлы, молчащие на ICMP.
- **Врата** — проверки конкретных сервисов (HTTPS / TCP / PING): видно, когда провайдер душит один сервис, а общий пинг в порядке.
- **Ауспик** — окно поверх игр и приложений с живым пингом и вратами, ведёт поминутный дневник.
- **Страж** — дежурит в трее, оповещает о падении связи или туннеля и записывает простои.
- **Летопись** — история всех приговоров, графики потерь и сводка.
- Распознаёт туннели WireGuard / AmneziaWG, sing-box (Throne, Nekoray, Hiddify), Xray, Clash, OpenVPN и системный прокси.
- Русский и английский интерфейс.

Когитатор ничего не меняет в сетевых настройках — только смотрит и проверяет. Данные хранятся локально в `%APPDATA%\Cogitator`.

### Установка

Скачай `Cogitator.exe` со страницы [Releases](../../releases) и запусти. Установка не нужна, требуется .NET Framework 4.8 (есть в любой Windows 10/11).
Файл не подписан, поэтому SmartScreen может предупредить: «Подробнее → Выполнить в любом случае».

## English

The cogitator answers "whose fault is it": your home network, the ISP, the VPN server or the path in between.

- **Sanctums** — a registry of your VPN servers, one of them active.
- **Rituals** — five diagnostic runs: from a quick router/internet/DNS check to a full verdict with traceroute (direct and through the tunnel), ASN owners of every hop, MTU probing and a path map.
- **Sonar** — background traceroute to 1.1.1.1 with per-hop latency and loss.
- **Gates** — per-service checks (HTTPS / TCP / PING) to catch throttling of a single service.
- **Auspex** — an always-on-top overlay with live ping and gates, keeping a per-minute log.
- **Warden** — tray watcher that alerts when the link or the tunnel drops and records downtime.
- **Chronicle** — history of all verdicts, loss charts and a summary.
- Russian and English UI.

The cogitator never changes network settings — it only observes and probes. Data is stored locally in `%APPDATA%\Cogitator`.

Download `Cogitator.exe` from [Releases](../../releases). No install needed; requires .NET Framework 4.8 (built into Windows 10/11). The binary is unsigned, so SmartScreen may warn: "More info → Run anyway".

## Build

```
dotnet build -c Release -o out      # Windows
./build.sh                          # Linux/macOS with Mono
```

## License

Code — [MIT](LICENSE) © KeRR. Fonts — see [assets/fonts/LICENSE-FONTS.md](assets/fonts/LICENSE-FONTS.md).
