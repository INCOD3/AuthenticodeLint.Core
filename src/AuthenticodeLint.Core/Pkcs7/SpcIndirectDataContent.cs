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
            var contents = AsnReader.Read<AsnSequence, AsnSequence>(sequence);
            DigestInfo = new SpcDigestInfo(contents.Item2);
            Data = new SpcAttributeTypeAndOptionalValue(contents.Item1);
        }
    }

    public sealed class SpcAttributeTypeAndOptionalValue
    {
        public string Type { get; }
        public ArraySegment<byte>? Contents { get; }


        public SpcAttributeTypeAndOptionalValue(AsnSequence sequence)
        {
            var reader = new AsnConstructedReader(sequence);
            AsnObjectIdentifier type;
            AsnElement value;
            if (!reader.MoveNext(out type))
            {
                throw new Pkcs7Exception("Unable to read ObjectIdentifier from PE.");
            }
            if (reader.MoveNext(out value))
            {
                Contents = value.ElementData;
            }
            else
            {
                Contents = null;
            }
            Type = type.Value;
        }
    }

    public sealed class SpcDigestInfo
    {
        public AlgorithmIdentifier AlgorithmIdentifier { get; }
        public ArraySegment<byte> Digest { get; }

        public SpcDigestInfo(AsnSequence sequence)
        {
            var contents = AsnReader.Read<AsnSequence, AsnOctetString>(sequence);
            AlgorithmIdentifier = new AlgorithmIdentifier(contents.Item1);
            Digest = contents.Item2.Value;
        }
    }
}