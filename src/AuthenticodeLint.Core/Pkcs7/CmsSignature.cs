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
                using (var algorithm = HashAlgorithmFactory.FromOid(signer.DigestAlgorithm.Algorithm))
                using (var bhs = new BlockHashStream(algorithm))
                {
                    bhs.Write(data.ContentInfo.Content.ContentData);
                    if (signer.AuthenticatedAttributes.Count > 0) //There should *always* be at least two here if there are any
                    {
                        AsnPrinter.Print(Console.Out, signer.AuthenticatedAttributes.AsnElement.Reinterpret<AsnSet>());
                        var attributeContents = signer.AuthenticatedAttributes.AsnElement.Reinterpret<AsnSet>().ElementData;
                        bhs.Write(attributeContents);

                    }

                    var digest = await bhs.Digest();
                    byte[] digest2;
                    //TEST
                    using(var ms = new System.IO.MemoryStream())
                    {
                        ms.Write(data.ContentInfo.Content.ContentData);
                        var attributeContents = signer.AuthenticatedAttributes.AsnElement.Reinterpret<AsnSet>().ElementData;
                        ms.Write(attributeContents);
                        ms.Position = 0;
                        digest2 = algorithm.ComputeHash(ms);

                    //END TEST
                    var dummyCert = data.Certificates.First();

                    Dump(digest);
                    Dump(digest2);
                    ms.Position = 0;
                    var key = new x509Key(dummyCert.PublicKey);
                    var THEBIGONE = key.VerifyHash(digest, signer.EncryptedDigest.Value.AsArray());
                    var THEBIGONE2 = key.VerifyHash(digest2, signer.EncryptedDigest.Value.AsArray());
                    var THEBIGONE3 = dummyCert.AsCore().GetECDsaPublicKey().VerifyHash(digest2, signer.EncryptedDigest.Value.AsArray());
                    var THEBIGONE4 = dummyCert.AsCore().GetECDsaPublicKey().VerifyData(ms, signer.EncryptedDigest.Value.AsArray(), HashAlgorithmName.SHA1);
                    Console.WriteLine("THE BIG ONE: {0}", THEBIGONE);
                    Console.WriteLine("THE BIG ONE 2: {0}", THEBIGONE2);
                    Console.WriteLine("THE BIG ONE 3: {0}", THEBIGONE3);
                    Console.WriteLine("THE BIG ONE 4: {0}", THEBIGONE4);
                    }
                }
            }
            return false;
        }

        private void Dump(byte[] data)
        {
            Console.WriteLine(string.Join("", data.Select(b => b.ToString("X2"))));
        }
    }
}