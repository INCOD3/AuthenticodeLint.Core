using System.Threading.Tasks;

class Program
{
    static int Main(string[] args) => Run(args).GetAwaiter().GetResult();

    static async Task<int> Run(string[] args)
    {
        return 0;
    }
}
