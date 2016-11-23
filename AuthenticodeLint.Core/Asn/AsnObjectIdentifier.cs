using System;

namespace AuthenticodeLint.Core.Asn
{

    public sealed class AsnObjectIdentifier : AsnElement
    {
        public string Value { get; }

        public AsnObjectIdentifier(AsnTag tag, ArraySegment<byte> contentData) : base(tag, contentData)
        {
            var builder = new System.Text.StringBuilder();
            var firstOctet = contentData.Array[contentData.Offset] / 40;
            var secondOctet = contentData.Array[contentData.Offset] % 40;
            builder.Append(firstOctet);
            builder.Append('.');
            builder.Append(secondOctet);
            var value = 0L;
            //Start at one since the first octet has special handling above
            for (var i = 1; i < contentData.Count; i++)
            {
                var item = contentData.Array[contentData.Offset + i];
                value <<= 7;
                if ((item & 0x80) == 0x80)
                {
                    value |= (byte)(item & 0x7F);
                }
                else
                {
                    builder.Append('.');
                    builder.Append(value | item);
                    value = 0;
                }
            }
            if (value != 0)
            {
                throw new InvalidOperationException("ObjectIdentifier incorrectly terminated. Expecting more data.");
            }
            Value = builder.ToString();
        }

        public override string ToString() => Value;

        public override int GetHashCode() => Value.GetHashCode();
    }

}