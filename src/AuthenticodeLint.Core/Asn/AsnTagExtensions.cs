namespace AuthenticodeLint.Core.Asn
{
    public static class AsnTagExtensions
    {
        public static bool IsExImTag(this AsnTag tag, ulong value)
        {
            return (ulong)tag.Tag == value && tag.AsnClass != AsnClass.Univeral;
        }

        public static bool IsUniTag(this AsnTag tag, AsnTagValue value)
        {
            return tag.Tag == value && tag.AsnClass == AsnClass.Univeral;
        }
    }
}