using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public abstract class CmsAttribute
    {
        public string AttributeId { get; protected set; }
    }

    public class CmsGenericAttribute : CmsAttribute
    {
        public CmsGenericAttribute(string attributeId, AsnSet content)
        {
            AttributeId = attributeId;
            Content = content.ElementData;
        }

        public ArraySegment<byte> Content { get; }
    }

    public sealed class CmsMessageDigestAttibute : CmsGenericAttribute
    {
        public CmsMessageDigestAttibute(string attributeId, AsnSet content) : base(attributeId, content)
        {
            var digest = AsnContructedStaticReader.Read<AsnOctetString>(content);
            Digest = digest.Item1.Value;
        }

        public ArraySegment<byte> Digest { get; }
    }

    public sealed class CmsOpusAttribute : CmsGenericAttribute
    {
        public CmsOpusAttribute(string attributeId, AsnSet content) : base(attributeId, content)
        {
            var items = AsnContructedStaticReader.Read<AsnSequence>(content);
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
                var program = AsnContructedStaticReader.Read<AsnElement>(programName);
                ProgramName = DecodeSpcString(program.Item1);
            }

            if (moreInfo != null)
            {
                var more = AsnContructedStaticReader.Read<AsnElement>(moreInfo);
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
            if (element.Tag.IsExImTag(0))
            {
                var bmpProgramString = element.Reinterpret<AsnBmpString>();
                return bmpProgramString.Value;
            }
            else if (element.Tag.IsExImTag(1))
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

    public static class CmsAttributeDecoder
    {
        public static CmsAttribute Decode(AsnSequence sequence)
        {
            var properties = AsnContructedStaticReader.Read<AsnObjectIdentifier, AsnSet>(sequence);
            var attributeId = properties.Item1.Value;
            switch (attributeId)
            {
                case KnownOids.CmsPkcs9AttributeIds.messageDigest:
                    return new CmsMessageDigestAttibute(attributeId, properties.Item2);
                case KnownOids.CmsPkcs9AttributeIds.opusInfo:
                    return new CmsOpusAttribute(attributeId, properties.Item2);
                default:
                    return new CmsGenericAttribute(attributeId, properties.Item2);
            }
        }
    }
}