using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsSignature
    {
        private readonly AsnSequence _contentInfo;

        public CmsSignature(byte[] data) : this(new ArraySegment<byte>(data))
        {
        }

        public CmsSignature(ArraySegment<byte> data) : this(Decode(data))
        {
        }

        public CmsSignature(AsnSequence sequence)
        {
            _contentInfo = sequence;
            var items = AsnReader.Read<AsnObjectIdentifier, AsnElement>(_contentInfo);
            ContentType = MapFromOid(items.Item1.Value);
            var content = items.Item2;
            switch (ContentType)
            {
                case ContentType.Data:
                    Content = new CmsData(content);
                    break;
                case ContentType.SignedData:
                    Content = new CmsSignedData(content);
                    break;
                default:
                    throw new Pkcs7Exception($"ContentType {ContentType} is not supported.");
            }
        }

        private static AsnSequence Decode(ArraySegment<byte> data)
        {
            AsnElement decoded;
            if (!AsnDecoder.TryDecode(data, out decoded) || !(decoded is AsnSequence))
            {
                throw new Pkcs7Exception("Unable to parse PKCS#7 signature.");
            }
            return (AsnSequence)decoded;
        }

        public ContentType ContentType { get; }

        public CmsContent Content { get; }

        private static ContentType MapFromOid(string oid)
        {
            switch (oid)
            {
                case KnownOids.CmsContentTypes.signedData:
                    return ContentType.SignedData;
                case KnownOids.CmsContentTypes.data:
                    return ContentType.Data;
                case KnownOids.CmsContentTypes.envelopedData:
                    return ContentType.EnvelopedData;
                case KnownOids.CmsContentTypes.signedAndEnvelopedData:
                    return ContentType.SignedAndEnvelopedData;
                case KnownOids.CmsContentTypes.digestedData:
                    return ContentType.DigestedData;
                case KnownOids.CmsContentTypes.encryptedData:
                    return ContentType.EncryptedData;
                default:
                    throw new Pkcs7Exception($"Unknown ContentType identifier {oid}.");
            }
        }
    }
}