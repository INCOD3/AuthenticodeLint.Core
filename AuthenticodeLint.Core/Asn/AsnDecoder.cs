using System;

namespace AuthenticodeLint.Core.Asn
{
	/// <summary>
	/// Decodes asn1 encoded data.
	/// </summary>
	public static class AsnDecoder
	{
		public static AsnElement Decode(byte[] asnData) => Decode(new ArraySegment<byte>(asnData));

		public static AsnElement Decode(ArraySegment<byte> asnData)
		{
			int elementLength;
			return Process(asnData, out elementLength);
		}

		internal static AsnElement Process(ArraySegment<byte> data, out int elementLength)
		{
			var tagOctet = data.Array[data.Offset];
			int octetLength;
			var tag = ReadTag(tagOctet);
			var lengthWindow = new ArraySegment<byte>(data.Array, data.Offset + 1, data.Count - 1);
			var length = ReadTagLength(lengthWindow, out octetLength);
			var rawData = new ArraySegment<byte>(lengthWindow.Array, lengthWindow.Offset + octetLength, (int)length);
			elementLength = 1 + octetLength + checked((int)length);
			if (tag.AsnClass == AsnClass.Univeral)
			{
				switch (tag.Tag)
				{
					case AsnTagValue.Integer:
						return new AsnInteger(tag, rawData);
					case AsnTagValue.Boolean:
						return new AsnBoolean(tag, rawData);
					case AsnTagValue.BitString:
						return new AsnBitString(tag, rawData);
					case AsnTagValue.OctetString:
						return new AsnOctetString(tag, rawData);
					case AsnTagValue.ObjectIdentifier:
						return new AsnObjectIdentifier(tag, rawData);
					case AsnTagValue.IA5String:
						return new AsnIA5String(tag, rawData);
					case AsnTagValue.AsnNull:
						return new AsnNull(tag, rawData);
					case AsnTagValue.SequenceSequenceOf:
						return new AsnSequence(tag, rawData);
					case AsnTagValue.SetSetOf:
						return new AsnSet(tag, rawData);
					case AsnTagValue.PrintableString:
						return new AsnPrintableString(tag, rawData);
					case AsnTagValue.UtcTime:
						return new AsnUtcTime(tag, rawData);
					case AsnTagValue.GeneralizedTime:
						return new AsnGeneralizedTime(tag, rawData);
				}
			}
			if (tag.Constructed)
			{
				return new AsnConstructed(tag, rawData);
			}
			else
			{
				return new AsnRaw(tag, rawData);
			}
		}

		private static AsnTag ReadTag(byte tag)
		{
			return new AsnTag((AsnTagValue)(tag & 0x1F), (AsnClass)((tag & 0xC0) >> 6), (tag & 0x20) == 0x20);
		}

		private static ulong ReadTagLength(ArraySegment<byte> data, out int octetLength)
		{
			var firstByte = data.Array[data.Offset];
			//This is a "unknown" length, which we don't support right now.
			if (firstByte == 0x80)
			{
				throw new NotSupportedException("Elements of unknown lengths are not supported.");
			}
			var isLongForm = (firstByte & 0x80) == 0x80;
			if (!isLongForm)
			{
				octetLength = 1;
				return firstByte;
			}
			int length = firstByte & 0x7F;
			octetLength = length + 1;
			ulong value = 0;
			for (var i = 0; i < length; i++)
			{
				value <<= 8;
				value |= data.Array[data.Offset + 1 + i];
			}
			return value;
		}
	}

	public enum AsnTagValue : byte
	{
		Boolean = 1,
		Integer = 2,
		BitString = 3,
		OctetString = 4,
		AsnNull = 5,
		ObjectIdentifier = 6,
		ObjectDescriptor = 7,
		InstanceOfExternal = 8,
		Real = 9,
		Enumerated = 10,
		EmbeddedPdv = 11,
		Utf8String = 12,
		RelativeOid = 13,
		SequenceSequenceOf = 16,
		SetSetOf = 17,
		NumericString = 18,
		PrintableString = 19,
		TeletexStringT61String = 20,
		VideotexString = 21,
		IA5String = 22,
		UtcTime = 23,
		GeneralizedTime = 24,
		GraphicString = 25,
		VisibleStringIso646String = 26,
		GeneralString = 27,
		UniversalString = 28,
		CharacterString = 29,
		BmpString = 30
	}

	public enum AsnClass : byte
	{
		Univeral = 0,
		Application = 1,
		ContextSpecific = 2,
		Private = 3
	}
}