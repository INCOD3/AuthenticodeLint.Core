using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticodeLint.Core.x509
{
    public sealed class x509Chain
    {
        public bool Successful { get; }
        public IReadOnlyList<x509Certificate> Chain { get; }

        private x509Chain(bool successful, IReadOnlyList<x509Certificate> chain)
        {
            Successful = successful;
            Chain = chain;
        }

        public static x509Chain Build(x509Certificate leaf, IEnumerable<x509Certificate> extraCertificates)
        {
            //Building chains is an extremely complex thing to do. Rely on corefx to do it for now
            using(var coreLeaf = leaf.AsCore())
            {
                var extrasCore = extraCertificates.Select(c => c.AsCore()).ToArray();
                try
                {
                    using (var coreChain = new X509Chain())
                    {
                        //All we care about is building a path. We're not using this
                        //for validation.
                        coreChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        coreChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                        coreChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                        coreChain.ChainPolicy.ExtraStore.AddRange(extrasCore);
                        var result = coreChain.Build(coreLeaf);
                        var chain = coreChain.ChainElements.Cast<X509ChainElement>().Select(c => x509Certificate.FromCore(c.Certificate)).ToList();
                        return new x509Chain(result, chain);
                    }
                }
                finally
                {
                    foreach(var coreCert in extrasCore)
                    {
                        coreCert.Dispose();
                    }
                }
            }
        }

        public static x509Chain Build(x509Certificate leaf) => Build(leaf, Array.Empty<x509Certificate>());
    }
}