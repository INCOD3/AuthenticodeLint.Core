using System;

namespace AuthenticodeLint.Core.Asn
{
	/// <summary>
	/// Decodes asn1 encoded data.
	/// </summary>
	public static class AsnDecoder
	{
		public static AsnElement Decode(byte[] asnData)
		{
			var data = new ArraySegment<byte>(asnData);
			int elementLength;
			return Process(data, out elementLength);
		}

		internal static AsnElement Process(ArraySegment<byte> data, out int elementLength)
		{
			var tag = data.Array[data.Offset];
			AsnClass asnClass;
			bool constructed;
			AsnTagType asnTagType;
			int octetLength;
			ReadTag(tag, out asnClass, out constructed, out asnTagType);
			var lengthWindow = new ArraySegment<byte>(data.Array, data.Offset + 1, data.Count - 1);
			var length = ReadTagLength(lengthWindow, out octetLength);
			var rawData = new ArraySegment<byte>(lengthWindow.Array, lengthWindow.Offset + octetLength, (int)length);
			elementLength = 1 + octetLength + checked((int)length);
			switch (asnTagType)
			{
				case AsnTagType.Integer:
					return new AsnInteger(asnTagType, rawData);
				case AsnTagType.Boolean:
					return new AsnBoolean(asnTagType, rawData);
				case AsnTagType.BitString:
					return new AsnBitString(asnTagType, rawData);
				case AsnTagType.OctetString:
					return new AsnOctetString(asnTagType, rawData);
				case AsnTagType.ObjectIdentifier:
					return new AsnObjectIdentifier(asnTagType, rawData);
				case AsnTagType.IA5String:
					return new AsnIA5String(asnTagType, rawData);
				case AsnTagType.AsnNull:
					return new AsnNull(asnTagType, rawData);
				case AsnTagType.SequenceSequenceOf:
					return new AsnSequence(asnTagType, rawData);
				default:
					return new AsnRaw(asnTagType, rawData);

			}
		}

		private static void ReadTag(byte tag, out AsnClass asnClass, out bool constructed, out AsnTagType asnTagType)
		{
			asnTagType = (AsnTagType)(tag & 0x1F);
			constructed = (tag & 0x20) == 0x20;
			asnClass = (AsnClass)((tag & 0xC0) >> 6);
		}

		private static ulong ReadTagLength(ArraySegment<byte> data, out int octetLength)
		{
			var firstByte = data.Array[data.Offset];
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

	public enum AsnTagType : byte
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