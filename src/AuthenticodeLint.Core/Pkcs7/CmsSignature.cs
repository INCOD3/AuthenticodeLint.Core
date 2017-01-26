using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AuthenticodeLint.Core.Asn;
using AuthenticodeLint.Core.x509;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsSignature : IVerifiableSignature
    {
        private readonly AsnSequence _contentInfo;
        private readonly bool _isNestedSignature;

        public CmsSignature(byte[] data) : this(new ArraySegment<byte>(data))
        {
        }

        public CmsSignature(ArraySegment<byte> data) : this(Decode(data))
        {
        }

        public CmsSignature(AsnSequence sequence, bool isNestedSignature)
        {
            _isNestedSignature = isNestedSignature;
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

        public CmsSignature(AsnSequence sequence) : this(sequence, false)
        {
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

        private static ContentType MapFromOid(Oid oid)
        {
            switch (oid.Value)
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
        public Task<bool> VerifySignature()
        {
            if (ContentType != ContentType.SignedData)
            {
                throw new NotSupportedException();
            }
            var data = (CmsSignedData)Content;

            //This could be done in parallel, but Authenticode signatures don't typically (can't?)
            //have more than one SignerInfo. Instead they use signature nesting.
            foreach (var signer in data.SignerInfos)
            {
                if (!data.DigestAlgorithms.Contains(signer.DigestAlgorithm))
                {
                    // The SignerInfo uses an algorithm that was not declared in the SignedData.
                    return Task.FromResult(false);
                }
                ArraySegment<byte> digest;
                var algorithm = HashAlgorithmFactory.FromOid(signer.DigestAlgorithm.Algorithm);
                using (var ih = IncrementalHash.CreateHash(algorithm))
                {
                    ih.AppendData(data.ContentInfo.Content.ContentData);
                    digest = ih.GetSegmentHashAndReset();
                }
                if (signer.AuthenticatedAttributes.Count == 0)
                {
                    throw new Pkcs7Exception("AuthenticatedAttribute required for non-detached signatures.");
                }
                var contentTypeAttribute = signer.AuthenticatedAttributes[KnownOids.CmsPkcs9AttributeIds.contentType] as CmsContentTypeAttribute;
                var digestAttribute = signer.AuthenticatedAttributes[KnownOids.CmsPkcs9AttributeIds.messageDigest] as CmsMessageDigestAttibute;
                if (digestAttribute == null)
                {
                    throw new Pkcs7Exception("MessageDigest attribute missing from authenticated attribute set.");
                }
                if (contentTypeAttribute == null && !_isNestedSignature)
                {
                    throw new Pkcs7Exception("Signature attributes is missing the content type attribute.");
                }
                else if (contentTypeAttribute != null && _isNestedSignature)
                {
                    throw new Pkcs7Exception("Nested signatures should not have a content type attribute.");
                }

                if (digest.Compare(digestAttribute.Digest) != 0)
                {
                    //This is the case where the messageDigest attribute does not match the digest of the
                    //signed data structure.
                    return Task.FromResult(false);
                }

                var authenticatedSet = signer.AuthenticatedAttributes.AsnElement.Reinterpret<AsnSet>();
                ArraySegment<byte> authenticatedAttributeDigest;
                var algorithmName = HashAlgorithmFactory.FromOid(signer.DigestAlgorithm.Algorithm);
                using (var ih = IncrementalHash.CreateHash(algorithmName))
                {
                    ih.AppendData(authenticatedSet.ElementData);
                    authenticatedAttributeDigest = ih.GetSegmentHashAndReset();
                }
                var certificateCollection = new x509CertificateCollection(data.Certificates);
                var cert = certificateCollection.FindFirstBy(signer.IssuerAndSerialNumber);
                using (var key = new x509Key(cert.PublicKey))
                {
                    var result = key.VerifyHash(authenticatedAttributeDigest, signer.EncryptedDigest.Value, signer.DigestAlgorithm.Algorithm);
                    if (!result)
                    {
                        //The signature over the authenticated attribute set is wrong. Stop processing all signatures and return "no".
                        return Task.FromResult(false);
                    }
                }
            }

            //If we got here then every SignerInfo didn't return "false", so the signature must be valid.
            return Task.FromResult(true);
        }
    }
}