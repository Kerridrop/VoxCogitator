#!/bin/sh
# Build without Windows using Mono (mcs). On Windows: dotnet build -c Release
set -e
mkdir -p out
mcs -sdk:4.5 -target:winexe -platform:anycpu -optimize+ -codepage:utf8 \
  -win32icon:assets/cog.ico \
  -resource:assets/fonts/FSEX.ttf,FSEX.ttf -resource:assets/fonts/CogDOS.ttf,CogDOS.ttf \
  -r:System.Windows.Forms.dll -r:System.Drawing.dll \
  -out:out/Cogitator.exe src/Cogitator.cs
