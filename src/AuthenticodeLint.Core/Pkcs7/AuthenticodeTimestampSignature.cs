using System;
using System.Linq;
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

        public async Task<bool> VerifySignature()
        {
            var data = (CmsSignedData) _pkcs7parent.Content;

            //We can't verify a parent signature that has more than one SignerInfo. That shouldn't
            //ever happen with Authenticode in the first place, but, we explicitly fail here if for
            //whatever reason it's encountered.
            if (data.SignerInfos.Count != 1)
            {
                return false;
            }
            var signer = _signature;
            if (!data.DigestAlgorithms.Contains(signer.DigestAlgorithm))
            {
                // The SignerInfo uses an algorithm that was not declared in the SignedData.
                return false;
            }
            ArraySegment<byte> digest;
            using (var algorithm = HashAlgorithmFactory.FromOid(signer.DigestAlgorithm.Algorithm))
            {
                //We already know there is exactly one SignerInfo.
                var encryptedDigest = data.SignerInfos[0].EncryptedDigest.Value;
                digest = new ArraySegment<byte>(algorithm.ComputeHash(encryptedDigest.Array, encryptedDigest.Offset, encryptedDigest.Count));
            }
            if (signer.AuthenticatedAttributes.Count == 0)
            {
                throw new Pkcs7Exception("AuthenticatedAttribute required for non-detached signatures.");
            }

            var digestAttribute = signer.AuthenticatedAttributes[KnownOids.CmsPkcs9AttributeIds.messageDigest] as CmsMessageDigestAttibute;
            if (digestAttribute == null)
            {
                throw new Pkcs7Exception("MessageDigest attribute missing from authenticated attribute set.");
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
            var certificateCollection = new x509CertificateCollection(data.Certificates);
            var cert = certificateCollection.FindFirstBy(signer.IssuerAndSerialNumber);
            using (var key = new x509Key(cert.PublicKey))
            {
                var result = key.VerifyHash(authenticatedAttributeDigest, signer.EncryptedDigest.Value, signer.DigestAlgorithm.Algorithm);
                if (!result)
                {
                    //The signature over the authenticated attribute set is wrong. Stop processing all signatures and return "no".
                    return false;
                }
            }
            return true;
        }
    }
}