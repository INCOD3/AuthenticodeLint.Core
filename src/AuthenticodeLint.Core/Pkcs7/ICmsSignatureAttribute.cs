namespace AuthenticodeLint.Core.Pkcs7
{
    public interface ICmsSignatureAttribute
    {
        CmsSignature Signature { get; }
    }
}