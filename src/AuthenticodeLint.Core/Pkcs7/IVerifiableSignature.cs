using System.Threading.Tasks;

namespace AuthenticodeLint.Core.Pkcs7
{
    public interface IVerifiableSignature
    {
        ValueTask<bool> VerifySignature();
    }
}