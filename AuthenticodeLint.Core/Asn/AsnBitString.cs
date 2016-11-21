using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnBitString : AsnElement
	{
		public ArraySegment<byte> Value { get; }

		public int UnusedBits { get; }

		public AsnBitString(AsnTag tag, ArraySegment<byte> data) : base(tag, data)
		{
			UnusedBits = data.Array[data.Offset];
			Value = new ArraySegment<byte>(data.Array, data.Offset + 1, data.Count - 1);
		}

		public override string ToString()
		{
			var builder = new StringBuilder();
			for (var i = 0; i < Value.Count; i++)
			{
				var b = Value.Array[Value.Offset + i];
				if (i < Value.Count - 1)
				{
					builder.Append((b & 0x80) > 0 ? "1" : "0");
					builder.Append((b & 0x40) > 0 ? "1" : "0");
					builder.Append((b & 0x20) > 0 ? "1" : "0");
					builder.Append((b & 0x10) > 0 ? "1" : "0");
					builder.Append((b & 0x08) > 0 ? "1" : "0");
					builder.Append((b & 0x04) > 0 ? "1" : "0");
					builder.Append((b & 0x02) > 0 ? "1" : "0");
					builder.Append((b & 0x01) > 0 ? "1" : "0");
				}
				else
				{
					for (var j = 0; j < 8 - UnusedBits; j++)
					{
						var mask = 0x80 >> j;
						builder.Append((b & mask) > 0 ? "1" : "0");
					}
				}
			}
			return builder.ToString();
		}
	}

}