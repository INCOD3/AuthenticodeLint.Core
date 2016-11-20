using System;
using System.Numerics;

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
			return Process(data);
		}

		private static AsnElement Process(ArraySegment<byte> data)
		{
			var tag = data.Array[data.Offset];
			AsnClass asnClass;
			bool constructed;
			AsnTagType asnTagType;
			int octetLength;
			ReadTag(tag, out asnClass, out constructed, out asnTagType);
			var lengthWindow = new ArraySegment<byte>(data.Array, data.Offset + 1, data.Count - 1);
			var length = ReadVariableLength(lengthWindow, out octetLength);
			var rawData = new ArraySegment<byte>(lengthWindow.Array, lengthWindow.Offset + octetLength, lengthWindow.Count - octetLength);
			switch (asnTagType)
			{
				case AsnTagType.Integer:
					return new AsnInteger(rawData);
				default:
					throw new NotImplementedException();
						
			}
		}

		private static void ReadTag(byte tag, out AsnClass asnClass, out bool constructed, out AsnTagType asnTagType)
		{
			asnTagType = (AsnTagType)(tag & 0x1F);
			constructed = (tag & 0x20) == 0x20;
			asnClass = (AsnClass)((tag & 0xC0) >> 6);
		}

		internal static ulong ReadVariableLength(ArraySegment<byte> data, out int octetLength)
		{
			var value = 0UL;
			for (var i = 0; i < 8; i++)
			{
				byte octet = data.Array[data.Offset + i];
				if ((octet & 0x80) == 0x80)
				{
					ulong bigOctet = octet & 0x7FUL;
					value |= bigOctet << (i * 8);
				}
				else
				{
					ulong bigOctet = octet;
					value |= bigOctet << (i * 8);
					octetLength = i+1;
					return value;
				}
			}
			throw new Exception("asn1 encoded length exceeds 8 octets.");
		}
	}

	/// <summary>
	/// An asn1 element. All elements inherit from this type.
	/// </summary>
	public abstract class AsnElement
	{
		/// <summary>
		/// Gets the segement of data for the element.
		/// </summary>
		public ArraySegment<byte> Data { get; }

		public AsnElement(ArraySegment<byte> data)
		{
			Data = data;
		}
	}

	/// <summary>
	/// A signed asn1 integer.
	/// </summary>
	public sealed class AsnInteger : AsnElement
	{
		/// <summary>
		/// The value of the integer.
		/// </summary>
		public BigInteger Value { get; }

		public AsnInteger(ArraySegment<byte> data) : base(data)
		{
			var buffer = new byte[data.Count];
			for (int i = data.Count - 1, j = 0; i >= 0; i--, j++)
			{
				buffer[j] = data.Array[data.Offset + i];
			}
			Value = new BigInteger(buffer);
		}
	}

	public sealed class AsnUknownElement : AsnElement
	{
		public AsnUknownElement(ArraySegment<byte> data) : base(data)
		{
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

	internal enum AsnClass : byte
	{
		Univeral = 0,
		Application = 1,
		ContextSpecific = 2,
		Private = 3
	}
}