using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsOpusAttribute : CmsGenericAttribute
    {
        public CmsOpusAttribute(string attributeId, AsnSet content) : base(attributeId, content)
        {
            var items = AsnReader.Read<AsnSequence>(content);
            AsnConstructed programName = null, moreInfo = null;
            var reader = new AsnConstructedReader(items.Item1);
            AsnConstructed next;
            while (reader.MoveNext(out next))
            {
                if (next.Tag.IsExImTag(0))
                {
                    programName = next;
                }
                else if (next.Tag.IsExImTag(1))
                {
                    moreInfo = next;
                }
            }
            if (programName != null)
            {
                var program = AsnReader.Read<AsnElement>(programName);
                ProgramName = DecodeSpcString(program.Item1);
            }

            if (moreInfo != null)
            {
                var more = AsnReader.Read<AsnElement>(moreInfo);
                if (more.Item1.Tag.IsExImTag(0))
                {
                    var moreString = more.Item1.Reinterpret<AsnIA5String>();
                    MoreInfo = moreString.Value;
                    MoreInfoType = InfoType.Url;
                }
                else if (more.Item1.Tag.IsExImTag(1))
                {
                    MoreInfoType = InfoType.Moniker;
                }
                else if (more.Item1.Tag.IsExImTag(2))
                {
                    MoreInfoType = InfoType.File;
                }
                else
                {
                    throw new Pkcs7Exception("Unable to decode MoreInfo data.");
                }
            }
        }

        private static string DecodeSpcString(AsnElement element)
        {
            if (element.Tag.IsExImTag(0)) //0 is an implicit tag for a BmpString
            {
                var bmpProgramString = element.Reinterpret<AsnBmpString>();
                return bmpProgramString.Value;
            }
            else if (element.Tag.IsExImTag(1)) //1 is an implicit tag for a IA5String
            {
                var ia5ProgramString = element.Reinterpret<AsnIA5String>();
                return ia5ProgramString.Value;
            }
            else
            {
                throw new Pkcs7Exception("Unable to decode SpcString data.");
            }
        }

        public string ProgramName { get; }
        public string MoreInfo { get; }
        public InfoType MoreInfoType { get; }

        public enum InfoType
        {
            Url,
            File,
            Moniker,
        }
    }
}