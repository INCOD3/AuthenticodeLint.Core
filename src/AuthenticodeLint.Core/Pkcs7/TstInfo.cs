using System;
using System.IO;
using AuthenticodeLint.Core.Asn;
using AuthenticodeLint.Core.x509;

namespace AuthenticodeLint.Core.Pkcs7
{
    /// <summary>
    /// Time-stamp Token Info.
    public sealed class TstInfo
    {
        private readonly AsnSequence _sequence;

        public int Version { get; }
        public Oid PolicyId { get; }
        public TstInfoMessageImprint MessageImprint { get; }
        public ArraySegment<byte> SerialNumber { get; }
        public DateTimeOffset GeneralizedTime { get; }
        public TstAccuracy Accuracy { get; }
        public bool Ordering { get; }
        public ArraySegment<byte>? Nonce { get; }
        public GeneralName Tsa { get; }
        public x509Extensions Extensions { get; }

        public TstInfo(AsnSequence sequence)
        {
            _sequence = sequence;
            var reader = new AsnConstructedReader(sequence);
            AsnInteger version, serialNumber;
            AsnObjectIdentifier policyId;
            AsnSequence messageImprint;
            AsnGeneralizedTime genTime;
            if (!reader.MoveNext(out version))
            {
                throw new Pkcs7Exception("Missing version number for TST.");
            }
            if (!reader.MoveNext(out policyId))
            {
                throw new Pkcs7Exception("Missing PolicyId for TST.");
            }
            if (!reader.MoveNext(out messageImprint))
            {
                throw new Pkcs7Exception("Missing message imprint for TST.");
            }
            if (!reader.MoveNext(out serialNumber))
            {
                throw new Pkcs7Exception("Missing serial number for the TST.");
            }
            if (!reader.MoveNext(out genTime))
            {
                throw new Pkcs7Exception("Missing genTime for the TST.");
            }
            AsnElement next;
            AsnSequence extensions = null, tsa = null;
            while (reader.MoveNext(out next))
            {
                if (next.Tag.IsUniTag(AsnTagValue.Boolean)) //ordering
                {
                    Ordering = ((AsnBoolean)next).Value;
                }
                else if (next.Tag.IsUniTag(AsnTagValue.Integer)) //nonce
                {
                    Nonce = next.ContentData;
                }
                else if (next.Tag.IsUniTag(AsnTagValue.SequenceSequenceOf)) //accuracy
                {
                    Accuracy = new TstAccuracy((AsnSequence)next);
                }
                else if (next.Tag.IsExImTag(0) && tsa == null) //tsa, explicitly tagged
                {
                    tsa = AsnReader.Read<AsnSequence>((AsnConstructed)next);
                }
                else if (next.Tag.IsExImTag(1) && extensions == null) //extensions, implicitly tagged
                {
                    extensions = next.Reinterpret<AsnSequence>();
                }
            }
            Version = (int)version.Value;
            PolicyId = policyId.Value;
            MessageImprint = new TstInfoMessageImprint(messageImprint);
            SerialNumber = serialNumber.ContentData;
            GeneralizedTime = genTime.Value;
            Tsa = tsa == null ? null : new GeneralName(tsa);
            Extensions = extensions == null ? new x509Extensions() : new x509Extensions(extensions);
        }

        public override int GetHashCode() => _sequence.GetHashCode();

        public override string ToString()
        {
            var textWriter = new StringWriter();
            AsnPrinter.Print(textWriter, _sequence);
            return textWriter.ToString();
        }
    }
}