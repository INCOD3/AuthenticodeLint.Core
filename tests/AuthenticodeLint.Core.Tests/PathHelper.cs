using System.IO;
using System.Runtime.CompilerServices;

namespace AuthenticodeLint.Core.Tests
{
    public static class PathHelper
    {
        public static string CombineWithProjectPath(string path)
        {
            var thisPath = ThisPath();
            var directory = Path.GetDirectoryName(thisPath);
            return Path.Combine(directory, path);
        }

        private static string ThisPath([CallerFilePathAttribute]string path = "") => path;
    }
}