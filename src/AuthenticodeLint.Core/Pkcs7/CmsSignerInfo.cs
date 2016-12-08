using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsSignerInfo
    {
        private readonly AsnSequence _sequence;

        public CmsSignerInfo(AsnSequence sequence)
        {
            _sequence = sequence;
            var reader = new AsnConstructedReader(sequence);
            AsnInteger version;
            AsnSequence issuerAndSerial;
            if (!reader.MoveNext(out version))
            {
                throw new Pkcs7Exception("Unable to read SignerInfo version.");
            }
            if (!reader.MoveNext(out issuerAndSerial))
            {
                throw new Pkcs7Exception("Unable to read SignerInfo issuerAndSerialNumber.");
            }
            Version = (int)version.Value;
            IssuerAndSerialNumber = new CmsIssuerAndSerialNumber(issuerAndSerial);
        }

        public int Version { get; }
        public CmsIssuerAndSerialNumber IssuerAndSerialNumber { get; }
    }
}