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
            switch (obj)
            {
                case null:
                    return false;
                case AsnTag other:
                    return this == other;
                default:
                    return false;
            }
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

        public override string ToString() => $"Tag: {{{ (AsnClass == AsnClass.Univeral ? Tag.ToString() : ((ulong)Tag).ToString()) }}}; Class: {{{AsnClass}}}; Constructed: {{{Constructed}}};";
    }
}
