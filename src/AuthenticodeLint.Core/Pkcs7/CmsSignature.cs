using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AuthenticodeLint.Core.Asn;
using AuthenticodeLint.Core.x509;

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

        /// <summary>Verifies the signature of the contents.</summary>
        /// <returns>True if the signature is valid, otherwise false.</returns>
        public async Task<bool> VerifySignature()
        {
            if (ContentType != ContentType.SignedData)
            {
                throw new NotSupportedException();
            }
            var data = (CmsSignedData)Content;
            foreach (var signer in data.SignerInfos)
            {
                if (!data.DigestAlgorithms.Contains(signer.DigestAlgorithm))
                {
                    // The SignerInfo uses an algorithm that was not declared in the SignedData.
                    return false;
                }
                ArraySegment<byte> digest;
                using (var algorithm = HashAlgorithmFactory.FromOid(signer.DigestAlgorithm.Algorithm))
                using (var bhs = new BlockHashStream(algorithm))
                {
                    bhs.Write(data.ContentInfo.Content.ContentData);
                    digest = await bhs.Digest();
                }
                if (signer.AuthenticatedAttributes.Count == 0)
                {
                    throw new InvalidOperationException("AuthenticatedAttribute required for non-detached signatures.");
                }
                var digestAttribute = signer.AuthenticatedAttributes[KnownOids.CmsPkcs9AttributeIds.messageDigest] as CmsMessageDigestAttibute;
                if (digestAttribute == null)
                {
                    throw new InvalidOperationException("MessageDigest attribute missing from authenticated attribute set.");
                }
                if (digest.Compare(digestAttribute.Digest) != 0)
                {
                    //This is the case where the messageDigest attribute does not match the digest of the
                    //signed data structure.
                    return false;
                }

                var authenticatedSet = signer.AuthenticatedAttributes.AsnElement.Reinterpret<AsnSet>();
                ArraySegment<byte> authenticatedAttributeDigest;
                using (var algorithm = HashAlgorithmFactory.FromOid(signer.DigestAlgorithm.Algorithm))
                using (var bhs = new BlockHashStream(algorithm))
                {
                    bhs.Write(authenticatedSet.ElementData);
                    authenticatedAttributeDigest = await bhs.Digest();
                }

                //TODO: select the right certificate
                var testCert = data.Certificates.First();
                var key = new x509Key(testCert.PublicKey);
                var result = key.VerifyHash(authenticatedAttributeDigest, signer.EncryptedDigest.Value, signer.DigestAlgorithm.Algorithm);
                if (!result)
                {
                    return false;
                }
            }
            return true;
        }

        private void Dump(byte[] data)
        {
            Console.WriteLine(string.Join("", data.Select(b => b.ToString("X2"))));
        }
    }
}