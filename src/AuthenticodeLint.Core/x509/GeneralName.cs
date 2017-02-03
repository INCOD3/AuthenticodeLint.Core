using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    public sealed class GeneralName
    {
        public GeneralName(AsnElement element)
        {
            var constructed = (AsnConstructed)element;
            if (element.Tag.IsExImTag((ulong)GeneralNameKind.DirectoryName))
            {
                Kind = (GeneralNameKind)element.Tag.Tag;
                var value = new x500DistinguishedName(AsnReader.Read<AsnSequence>(constructed));
                Value = value;
            }
            else if (
                element.Tag.IsExImTag((ulong)GeneralNameKind.RFC822Name) ||
                element.Tag.IsExImTag((ulong)GeneralNameKind.DNSName) ||
                element.Tag.IsExImTag((ulong)GeneralNameKind.UniformResourceIdentifier)
                )
            {
                Kind = (GeneralNameKind)element.Tag.Tag;
                var value = AsnReader.Read<AsnIA5String>(constructed).Value;
                Value = value;
            }
            else if (element.Tag.IsExImTag((ulong)GeneralNameKind.IPAddress))
            {
                Kind = (GeneralNameKind)element.Tag.Tag;
                var value = AsnReader.Read<AsnOctetString>(constructed).Value;
                Value = value;
            }
            else if (element.Tag.IsExImTag((ulong)GeneralNameKind.RegisteredID))
            {
                Kind = (GeneralNameKind)element.Tag.Tag;
                var value = AsnReader.Read<AsnObjectIdentifier>(constructed).Value;
                Value = value;
            }
            else if (element.Tag.IsExImTag((ulong)GeneralNameKind.OtherName))
            {
                Kind = (GeneralNameKind)element.Tag.Tag;
                var value = new GeneralNameAnotherName(AsnReader.Read<AsnSequence>(constructed));
                Value = value;
            }
            else
            {
                throw new x509Exception($"Unable to decode GeneralName of {element.Tag}.");
            }
        }

        public object Value { get; }
        public GeneralNameKind Kind { get; }
    }

    public enum GeneralNameKind
    {
        OtherName = 0,
        RFC822Name = 1,
        DNSName = 2,
        X400Address = 3,
        DirectoryName = 4,
        EDIPartyName = 5,
        UniformResourceIdentifier = 6,
        IPAddress = 7,
        RegisteredID = 8
    }

    public sealed class GeneralNameAnotherName
    {
        public GeneralNameAnotherName(AsnSequence sequence)
        {
            var contents = AsnReader.Read<AsnObjectIdentifier, AsnConstructed>(sequence);
            TypeId = contents.Item1.Value;
            Contents = contents.Item2.ContentData;
        }

        public Oid TypeId { get; }
        public ArraySegment<byte> Contents { get; }
    }
}