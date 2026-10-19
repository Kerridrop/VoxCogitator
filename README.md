# Vox Cogitator · Когитатор Связи

Диагностика сети и VPN для Windows в духе старого ЭЛТ-терминала.
Network & VPN diagnostics for Windows with a CRT soul.

![Terminal](docs/home.png)

Когитатор ищет, где рвётся связь: дома, у провайдера, на VPN-сервере или по пути до него. Ритуалы проверяют сеть и туннель и выносят приговор, сонар и Ауспик следят за пингом в фоне, Страж сообщает о падениях, летопись хранит историю. Сетевые настройки он не трогает — только смотрит.

It finds where the link breaks — at home, at the ISP, on the VPN server or along the path — and keeps a chronicle of every verdict. It never changes network settings.

## Запуск · Run

Скачай `Cogitator.exe` из [Releases](../../releases) и запусти — установка не нужна (Windows 10/11).
Файл не подписан: если SmartScreen предупредит, нажми «Подробнее → Выполнить в любом случае».

Download `Cogitator.exe` from [Releases](../../releases) and run it. If SmartScreen warns: "More info → Run anyway".

## Сборка · Build

```
dotnet build -c Release -o out
```

## Лицензия · License

[MIT](LICENSE) © KeRR · шрифты / fonts: [LICENSE-FONTS](assets/fonts/LICENSE-FONTS.md)
