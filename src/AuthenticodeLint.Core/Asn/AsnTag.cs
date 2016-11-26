namespace AuthenticodeLint.Core.Asn
{
    public struct AsnTag
    {
        private readonly AsnTagValue _tag;
        private readonly AsnClass _asnClass;
        private readonly bool _constructed;

        public AsnTag(AsnTagValue tag, AsnClass asnClass, bool constructed)
        {
            _tag = tag;
            _asnClass = asnClass;
            _constructed = constructed;
        }

        public AsnTagValue Tag => _tag;
        public AsnClass AsnClass => _asnClass;
        public bool Constructed => _constructed;

        public override bool Equals(object obj)
        {
            if (obj == null || !(obj is AsnTag))
            {
                return false;
            }
            var other = (AsnTag)obj;
            return _tag == other._tag && _asnClass == other._asnClass && _constructed == other._constructed;
        }

        public static bool operator ==(AsnTag left, AsnTag right)
        {
            return left._tag == right._tag && left._asnClass == right._asnClass && left._constructed == right._constructed;
        }

        public static bool operator !=(AsnTag left, AsnTag right)
        {
            return left._tag != right._tag || left._asnClass != right._asnClass || left._constructed != right._constructed;
        }

        public override int GetHashCode() =>
            //Bit 0: constructed
            //Bit 1-8: asn class
            //Bit 9-16: asn tag
            ((int)_tag << 9) | ((int)_asnClass << 1) | (_constructed ? 1 : 0);
    }
}
