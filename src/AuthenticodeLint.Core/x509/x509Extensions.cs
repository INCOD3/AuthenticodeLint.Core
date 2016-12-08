using System.Collections;
using System.Collections.Generic;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    public sealed class x509Extenions : IReadOnlyList<x509Extension>
    {
        private readonly List<x509Extension> _internalList;

        internal x509Extenions()
        {
            _internalList = new List<x509Extension>();
        }

        internal x509Extenions(AsnSequence sequence)
        {
            _internalList = new List<x509Extension>();
            var reader = new AsnConstructedReader(sequence);
            var itemReader = new AsnConstructedReader();
            AsnSequence element;
            while (reader.MoveNext(out element))
            {
                itemReader.ReTarget(element);
                AsnObjectIdentifier identifier;
                AsnBoolean critical;
                AsnOctetString content;
                bool isCritical = false;
                if (!itemReader.MoveNext(out identifier))
                {
                    throw new x509Exception("asn.1 extension is missing ObjectIdentifier");
                }
                if (itemReader.MoveNext(out critical))
                {
                    isCritical = critical.Value;
                }
                if (!itemReader.MoveNext(out content))
                {
                    throw new x509Exception("asn.1 extension is missing content.");
                }
                switch (identifier.Value)
                {
                    case KnownOids.CertificateExtensions.id_ce_basicConsraints:
                        _internalList.Add(new BasicConstraintsExtension(identifier.Value, content.Value, isCritical));
                        break;
                    case KnownOids.CertificateExtensions.id_ce_extKeyUsage:
                        _internalList.Add(new ExtendedKeyUsageExtension(identifier.Value, content.Value, isCritical));
                        break;
                    default:
                        _internalList.Add(new x509Extension(identifier.Value, content.Value, isCritical));
                        break;
                }
            }
        }

        public x509Extension this[int index] => _internalList[index];

        public int Count => _internalList.Count;

        public IEnumerator<x509Extension> GetEnumerator() => _internalList.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}