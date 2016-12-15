using System;
using System.Linq;
using System.Threading.Tasks;
using AuthenticodeLint.Core.PE;

class Program
{
    static int Main(string[] args)
    {
        return Run(args).GetAwaiter().GetResult();
    }

    static async Task<int> Run(string[] args)
    {
        using (var pe = new PortableExecutable("/Users/kjones/ff.exe"))
        {
            var header = await pe.GetDosHeaderAsync();
            var pe2 = await pe.GetPeHeaderAsync(header);
            Console.WriteLine(header.ExeFileHeaderAddress);
            Console.WriteLine(pe2.Architecture);
            var security = pe2.DataDirectories[ImageDataDirectoryEntry.IMAGE_DIRECTORY_ENTRY_SECURITY];
            Console.WriteLine(security.Size);
            var directory = pe.ReadDataDirectory(security);
            var all = new byte[security.Size];
            directory.Read(all, 0, (int)security.Size);
            Console.WriteLine(Convert.ToBase64String(all.Skip(8).ToArray()));
        }
        return 0;
    }
}
