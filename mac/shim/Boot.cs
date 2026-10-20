using Avalonia;
using Avalonia.Skia;
namespace System.Windows.Forms
{
    static class Boot
    {
        public static void Start()
        {
            AppBuilder.Configure<ShimApp>().UsePlatformDetect().UseSkia().StartWithClassicDesktopLifetime(new string[0]);
        }
    }
}
