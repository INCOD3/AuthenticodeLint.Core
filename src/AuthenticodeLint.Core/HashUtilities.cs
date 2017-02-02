using System.Security.Cryptography;
using static AuthenticodeLint.Core.Asn.KnownOids.Algorithms.SignatureAlgorithms;

namespace AuthenticodeLint.Core
{
    public static class HashUtilities
    {
        public static bool TryHashNameFromSignatureHashOid(Oid oid, out HashAlgorithmName hash, out SignatureAlgorithm signature)
        {
            switch (oid.Value)
            {
                case rsaWithMd5:
                    hash = HashAlgorithmName.MD5;
                    signature = SignatureAlgorithm.Rsa;
                    return true;
                case ecdsaWithSha1:
                    hash = HashAlgorithmName.SHA1;
                    signature = SignatureAlgorithm.Ecc;
                    return true;
                case rsaWithSha1:
                    hash = HashAlgorithmName.SHA1;
                    signature = SignatureAlgorithm.Rsa;
                    return true;
                case ecdsaWithSha256:
                    hash = HashAlgorithmName.SHA256;
                    signature = SignatureAlgorithm.Ecc;
                    return true;
                case rsaWithSha256:
                    hash = HashAlgorithmName.SHA256;
                    signature = SignatureAlgorithm.Rsa;
                    return true;
                case ecdsaWithSha384:
                    hash = HashAlgorithmName.SHA384;
                    signature = SignatureAlgorithm.Ecc;
                    return true;
                case rsaWithSha384:
                    hash = HashAlgorithmName.SHA384;
                    signature = SignatureAlgorithm.Rsa;
                    return true;
                case ecdsaWithSha512:
                    hash = HashAlgorithmName.SHA512;
                    signature = SignatureAlgorithm.Ecc;
                    return true;
                case rsaWithSha512:
                    hash = HashAlgorithmName.SHA512;
                    signature = SignatureAlgorithm.Rsa;
                    return true;
                default:
                    hash = default(HashAlgorithmName);
                    signature = default(SignatureAlgorithm);
                    return false;
            }
        }
    }
}