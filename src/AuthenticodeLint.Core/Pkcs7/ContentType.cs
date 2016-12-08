namespace AuthenticodeLint.Core.Pkcs7
{
    public enum ContentType : byte
    {
        Data = 1,
        SignedData = 2,
        EnvelopedData = 3,
        SignedAndEnvelopedData = 4,
        DigestedData = 5,
        EncryptedData = 6
    }
}