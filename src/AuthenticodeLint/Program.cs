using System.Threading.Tasks;

class Program
{
    static int Main(string[] args) => Run(args).GetAwaiter().GetResult();

    static ValueTask<int> Run(string[] args)
    {
        return new ValueTask<int>(0);
    }
}
