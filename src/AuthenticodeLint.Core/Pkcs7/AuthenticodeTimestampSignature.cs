using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AuthenticodeLint.Core.Asn;
using AuthenticodeLint.Core.x509;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class AuthenticodeTimestampSignature : IVerifiableSignature
    {
        private readonly CmsSignerInfo _signature;
        private readonly CmsSignature _pkcs7parent;

        public AuthenticodeTimestampSignature(CmsSignerInfo signature, CmsSignature pkcs7parent)
        {
            _signature = signature;
            _pkcs7parent = pkcs7parent;
        }

        public Task<bool> VerifySignature()
        {
            var data = (CmsSignedData) _pkcs7parent.Content;

            //We can't verify a parent signature that has more than one SignerInfo. That shouldn't
            //ever happen with Authenticode in the first place, but, we explicitly fail here if for
            //whatever reason it's encountered.
            if (data.SignerInfos.Count != 1)
            {
                return Task.FromResult(false);
            }
            if (!data.DigestAlgorithms.Contains(_signature.DigestAlgorithm))
            {
                // The SignerInfo uses an algorithm that was not declared in the SignedData.
                return Task.FromResult(false);
            }
            ArraySegment<byte> digest;
            var algorithmName = HashAlgorithmFactory.FromOid(_signature.DigestAlgorithm.Algorithm);
            using (var ih = IncrementalHash.CreateHash(algorithmName))
            {
                //We already know there is exactly one SignerInfo.
                var encryptedDigest = data.SignerInfos[0].EncryptedDigest.Value;
                ih.AppendData(encryptedDigest);
                digest = ih.GetSegmentHashAndReset();
            }
            if (_signature.AuthenticatedAttributes.Count == 0)
            {
                throw new Pkcs7Exception("AuthenticatedAttribute required for non-detached signatures.");
            }

            var digestAttribute = _signature.AuthenticatedAttributes[KnownOids.CmsPkcs9AttributeIds.messageDigest] as CmsMessageDigestAttibute;
            if (digestAttribute == null)
            {
                throw new Pkcs7Exception("MessageDigest attribute missing from authenticated attribute set.");
            }

            if (digest.Compare(digestAttribute.Digest) != 0)
            {
                //This is the case where the messageDigest attribute does not match the digest of the
                //signed data structure.
                return Task.FromResult(false);
            }

            var authenticatedSet = _signature.AuthenticatedAttributes.AsnElement.Reinterpret<AsnSet>();
            ArraySegment<byte> authenticatedAttributeDigest;
            var digestAlgorithmName = HashAlgorithmFactory.FromOid(_signature.DigestAlgorithm.Algorithm);
            using (var ih = IncrementalHash.CreateHash(digestAlgorithmName))
            {
                ih.AppendData(authenticatedSet.ElementData);
                authenticatedAttributeDigest = ih.GetSegmentHashAndReset();
            }
            var certificateCollection = new x509CertificateCollection(data.Certificates);
            var cert = certificateCollection.FindFirstBy(_signature.IssuerAndSerialNumber);
            using (var key = new x509Key(cert.PublicKey))
            {
                var result = key.VerifyHash(authenticatedAttributeDigest, _signature.EncryptedDigest.Value, _signature.DigestAlgorithm.Algorithm);
                if (!result)
                {
                    //The signature over the authenticated attribute set is wrong. Stop processing all signatures and return "no".
                    return Task.FromResult(false);
                }
            }
            return Task.FromResult(true);
        }
    }
}