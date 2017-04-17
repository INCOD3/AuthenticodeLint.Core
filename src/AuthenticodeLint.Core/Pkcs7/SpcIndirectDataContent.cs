using System;
using AuthenticodeLint.Core.Asn;
using AuthenticodeLint.Core.x509;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class SpcIndirectDataContent
    {
        public SpcDigestInfo DigestInfo { get; }
        public SpcAttributeTypeAndOptionalValue Data { get; }

        public SpcIndirectDataContent(AsnSequence sequence)
        {
            var (asnData, asnDigestInfo) = AsnReader.Read<AsnSequence, AsnSequence>(sequence);
            DigestInfo = new SpcDigestInfo(asnDigestInfo);
            Data = new SpcAttributeTypeAndOptionalValue(asnData);
        }
    }

    public sealed class SpcAttributeTypeAndOptionalValue
    {
        public Oid Type { get; }
        public ArraySegment<byte>? Contents { get; }


        public SpcAttributeTypeAndOptionalValue(AsnSequence sequence)
        {
            var reader = new AsnConstructedReader(sequence);
            if (reader.MoveNext(out AsnObjectIdentifier type))
            {
                Type = type.Value;
            }
            else
            {
                throw new Pkcs7Exception("Unable to read ObjectIdentifier from PE.");
            }
            if (reader.MoveNext(out AsnElement value))
            {
                Contents = value.ElementData;
            }
            else
            {
                Contents = null;
            }
        }
    }

    public sealed class SpcDigestInfo
    {
        public AlgorithmIdentifier AlgorithmIdentifier { get; }
        public ArraySegment<byte> Digest { get; }

        public SpcDigestInfo(AsnSequence sequence)
        {
            var (asnAlgorithmIdentifier, asnDigest) = AsnReader.Read<AsnSequence, AsnOctetString>(sequence);
            AlgorithmIdentifier = new AlgorithmIdentifier(asnAlgorithmIdentifier);
            Digest = asnDigest.Value;
        }
    }
}