using System.Threading.Tasks;

class Program
{
    static int Main(string[] args) => Run(args).GetAwaiter().GetResult();

    static Task<int> Run(string[] args)
    {
        return Task.FromResult(0);
    }
}
