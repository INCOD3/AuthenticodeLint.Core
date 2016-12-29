using System;
using AuthenticodeLint.Core.Asn;
using AuthenticodeLint.Core.x509;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class TstInfoMessageImprint
    {
        public AlgorithmIdentifier HashAlgorithm  { get; }
        public ArraySegment<byte> HashedMessage { get; }

        public TstInfoMessageImprint(AsnSequence sequence)
        {
            var items = AsnReader.Read<AsnSequence, AsnOctetString>(sequence);
            HashAlgorithm = new AlgorithmIdentifier(items.Item1);
            HashedMessage = items.Item2.Value;
        }
    }
}