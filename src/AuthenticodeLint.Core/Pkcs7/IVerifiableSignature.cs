using System.Threading.Tasks;

namespace AuthenticodeLint.Core.Pkcs7
{
    public interface IVerifiableSignature
    {
        Task<bool> VerifySignature();
    }
}