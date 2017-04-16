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
            var (asnAlgorithm, asnMessage) = AsnReader.Read<AsnSequence, AsnOctetString>(sequence);
            HashAlgorithm = new AlgorithmIdentifier(asnAlgorithm);
            HashedMessage = asnMessage.Value;
        }
    }
}