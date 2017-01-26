using System;
using System.Security.Cryptography;
using static AuthenticodeLint.Core.Asn.KnownOids.Algorithms.Digest;

namespace AuthenticodeLint.Core.Pkcs7
{
    public static class HashAlgorithmFactory
    {
        public static HashAlgorithmName FromOid(Oid oid)
        {
            switch (oid.Value)
            {
                case sha1:
                    return HashAlgorithmName.SHA1;
                case sha256:
                    return HashAlgorithmName.SHA256;
                default:
                    throw new InvalidOperationException($"Hash algorithm {oid} is not supported.");
            }
        }
    }
}