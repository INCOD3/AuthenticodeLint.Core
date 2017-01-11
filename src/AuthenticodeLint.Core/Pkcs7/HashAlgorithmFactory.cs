using System;
using System.Security.Cryptography;
using static AuthenticodeLint.Core.Asn.KnownOids.Algorithms.Digest;

namespace AuthenticodeLint.Core.Pkcs7
{
    public static class HashAlgorithmFactory
    {
        public static HashAlgorithm FromOid(string oid)
        {
            switch (oid)
            {
                case sha1:
                    return SHA1.Create();
                case sha256:
                    return SHA256.Create();
                default:
                    throw new InvalidOperationException($"Hash algorithm {oid} is not supported.");
            }
        }
    }
}