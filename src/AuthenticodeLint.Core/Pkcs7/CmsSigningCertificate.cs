using System;
using System.Collections.Generic;
using System.Linq;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsSigningCertificate
    {
        public IReadOnlyList<CmsCertificateId> CertificateIds { get; }

        public CmsSigningCertificate(AsnSequence sequence)
        {
            var reader = new AsnConstructedReader(sequence);
            AsnSequence essCertIds, policies;
            if (!reader.MoveNext(out essCertIds))
            {
                throw new Pkcs7Exception("Encoding SigningCertificate missing ESSCertId.");
            }
            if (!reader.MoveNext(out policies))
            {
                policies = null;
            }
            var certs = new List<CmsCertificateId>();
            foreach (var cert in essCertIds.Cast<AsnSequence>())
            {
                certs.Add(new CmsCertificateId(cert));
            }
            CertificateIds = certs.AsReadOnly();
        }
    }

    public sealed class CmsCertificateId
    {
        public CmsCertificateId(AsnSequence sequence)
        {
            var reader = new AsnConstructedReader(sequence);
            AsnOctetString certHash;
            AsnSequence issuerSerial;
            if (!reader.MoveNext(out certHash))
            {
                throw new Pkcs7Exception("Certificate ID does not contain hash.");
            }
            if (!reader.MoveNext(out issuerSerial))
            {
                issuerSerial = null;
            }
            Hash = certHash.Value;
            IssuerSerial = issuerSerial == null ? null : new CmsCertificateIssuerSerial(issuerSerial);
        }

        /// <summary>
        /// A SHA-1 thumbprint of the certificate that this ID is identifying.
        /// </summary>
        public ArraySegment<byte> Hash { get; }

        /// <summary>
        /// An issuer and serial number of the certificate this ID is identifying.
        /// </summary>
        public CmsCertificateIssuerSerial IssuerSerial { get; }
    }

    public sealed class CmsCertificateIssuerSerial
    {
        public CmsCertificateIssuerSerial(AsnSequence sequence)
        {
            var issuerSerial = AsnReader.Read<AsnSequence, AsnInteger>(sequence);
            var generalNames = issuerSerial.Item1;
            var serialNumber = issuerSerial.Item2;
            var generalNameReader = new AsnConstructedReader(generalNames);
            AsnElement generalName;
            //TODO: We need to read GeneralNames better. We need to read their implicit tags
            //and tease out the information from them.
            var generalNameList = new List<ArraySegment<byte>>(generalNames.Count);
            while (generalNameReader.MoveNext(out generalName))
            {
                generalNameList.Add(generalName.ContentData);
            }
            SerialNumber = serialNumber.ContentData;
            GeneralNames = generalNameList.AsReadOnly();
        }

        public ArraySegment<byte> SerialNumber { get; }
        public IReadOnlyList<ArraySegment<byte>> GeneralNames { get; }
    }
}