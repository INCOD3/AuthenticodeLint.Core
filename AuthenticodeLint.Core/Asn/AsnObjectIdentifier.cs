using System;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnObjectIdentifier : AsnElement
	{
		public string Value { get; }

		public AsnObjectIdentifier(AsnTagType tag, ArraySegment<byte> data) : base(tag, data)
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
				throw new InvalidOperationException();
			}
			Value = builder.ToString();
		}

		public override string ToString() => Value;

		public override int GetHashCode() => Value.GetHashCode();
	}

}