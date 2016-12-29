using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public struct TstAccuracy
    {
        private long _seconds;
        private short _millis;
        private short _micros;

        public TstAccuracy(AsnSequence sequence)
        {
            var reader = new AsnConstructedReader(sequence);
            AsnInteger seconds;
            if (!reader.MoveNext(out seconds))
            {
                throw new Pkcs7Exception("Unable to read seconds for accuracy.");
            }
            _seconds = (long)seconds.Value;
            _millis = 0;
            _micros = 0;
            AsnElement next;
            while (reader.MoveNext(out next))
            {
                if (next.Tag.IsExImTag(0))
                {
                    var millis = next.Reinterpret<AsnInteger>();
                    _millis = (short)millis.Value;
                }
                else if (next.Tag.IsExImTag(1))
                {
                    var micros = next.Reinterpret<AsnInteger>();
                    _micros = (short)micros.Value;
                }
            }
        }

        public long Seconds => _seconds;
        public short Milliseconds => _millis;
        public short Microseconds => _micros;
    }
}