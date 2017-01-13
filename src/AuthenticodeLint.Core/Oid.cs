using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core
{
    public sealed class Oid : IEquatable<Oid>
    {
        public string Value { get; }
        public ArraySegment<byte> Encoded { get; }

        public Oid(ArraySegment<byte> data)
        {
            var builder = new System.Text.StringBuilder();
            var firstOctet = data.Array[data.Offset] / 40;
            var secondOctet = data.Array[data.Offset] % 40;
            builder.Append(firstOctet);
            builder.Append('.');
            builder.Append(secondOctet);
            var value = 0L;
            //Start at one since the first octet has special handling above
            for (var i = 1; i < data.Count; i++)
            {
                var item = data.Array[data.Offset + i];
                //Shift the current value over to the left by 7 bits. OIDs are essentially
                //an array of 7-bit numbers where the 8th bit indicates if the value is continued
                //on to the next byte.
                value <<= 7;
                //If the 8th bit is set, then mask the value with the lower 7 bits and OR it with
                //the value we've been building so far.
                if ((item & 0x80) == 0x80)
                {
                    value |= (byte)(item & 0x7F);
                }
                //Otherwise, we've reached the end of this number. Append a dot to the string as a
                //separator.
                else
                {
                    builder.Append('.');
                    builder.Append(value | item);
                    value = 0;
                }
            }
            //By the time we get through everything, we should have a value of 0 being built. If it isn't
            //zero, then then OID is malformed - it ended with a byte that had its 8th bit set indicating
            //there was more data, but there wasn't any left to loop over. In this case, we just throw.
            if (value != 0)
            {
                throw new AsnException("ObjectIdentifier incorrectly terminated. Expecting more data.");
            }
            Value = builder.ToString();
            Encoded = data;
        }

        public override int GetHashCode() => Value.GetHashCode();

        public bool Equals(Oid other)
        {
            if (ReferenceEquals(other, null)) return false;
            if (ReferenceEquals(this, other)) return true;
            return StringComparer.Ordinal.Compare(Value, other.Value) == 0;
        }

        public override bool Equals(object obj) => Equals(obj as Oid);
        public override string ToString() => Value;

        public static bool operator ==(Oid left, Oid right)
        {
            if (ReferenceEquals(left, null) && ReferenceEquals(right, null)) return true;
            if (!ReferenceEquals(left, null) && ReferenceEquals(right, null)) return false;
            if (ReferenceEquals(left, null) && !ReferenceEquals(right, null)) return false;
            return left.Equals(right);
        }

        public static bool operator !=(Oid left, Oid right) => !(left == right);

        public static bool operator ==(string left, Oid right)
        {
            if (ReferenceEquals(left, null) && ReferenceEquals(right, null)) return true;
            if (!ReferenceEquals(left, null) && ReferenceEquals(right, null)) return false;
            if (ReferenceEquals(left, null) && !ReferenceEquals(right, null)) return false;
            return StringComparer.Ordinal.Compare(left, right.Value) == 0;
        }

        public static bool operator !=(string left, Oid right) => !(left == right);


        public static bool operator ==(Oid left, string right)
        {
            if (ReferenceEquals(left, null) && ReferenceEquals(right, null)) return true;
            if (!ReferenceEquals(left, null) && ReferenceEquals(right, null)) return false;
            if (ReferenceEquals(left, null) && !ReferenceEquals(right, null)) return false;
            return StringComparer.Ordinal.Compare(left.Value, right) == 0;
        }

        public static bool operator !=(Oid left, string right) => !(left == right);
    }
}