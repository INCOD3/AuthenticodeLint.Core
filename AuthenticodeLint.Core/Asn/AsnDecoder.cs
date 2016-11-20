using System;
using System.Collections.Generic;
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
					return new AsnInteger(rawData);
				case AsnTagType.Boolean:
					return new AsnBoolean(rawData);
				case AsnTagType.BitString:
					return new AsnBitString(rawData);
				case AsnTagType.OctetString:
					return new AsnOctetString(rawData);
				case AsnTagType.ObjectIdentifier:
					return new AsnObjectIdentifier(rawData);
				case AsnTagType.IA5String:
					return new AsnIA5String(rawData);
				case AsnTagType.AsnNull:
					return new AsnNull(rawData);
				case AsnTagType.SequenceSequenceOf:
					return new AsnSequence(rawData);
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
			octetLength = length+1;
			ulong value = 0;
			for (var i = 0; i < length; i++)
			{
				value <<= 8;
				value |= data.Array[data.Offset + 1 + i];
			}
			return value;
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

		protected AsnElement(ArraySegment<byte> data)
		{
			Data = data;
		}
	}

	/// <summary>
	/// A signed, big endian, asn1 integer.
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
			//BigInteger expects the number in little endian.
			for (int i = data.Count - 1, j = 0; i >= 0; i--, j++)
			{
				buffer[j] = data.Array[data.Offset + i];
			}
			Value = new BigInteger(buffer);
		}

		public override string ToString() => Value.ToString();
	}

	public sealed class AsnIA5String : AsnElement
	{
		public string Value { get; }

		public AsnIA5String(ArraySegment<byte> data) : base(data)
		{
			Value = System.Text.Encoding.ASCII.GetString(data.Array, data.Offset, data.Count);
		}

		public override string ToString() => Value;
	}

	public sealed class AsnUtf8String : AsnElement
	{
		public string Value { get; }

		public AsnUtf8String(ArraySegment<byte> data) : base(data)
		{
			Value = System.Text.Encoding.UTF8.GetString(data.Array, data.Offset, data.Count);
		}
	}

	public sealed class AsnBmpString : AsnElement
	{
		public string Value { get; }

		public AsnBmpString(ArraySegment<byte> data) : base(data)
		{
			Value = System.Text.Encoding.Unicode.GetString(data.Array, data.Offset, data.Count);
		}
	}



	public sealed class AsnObjectIdentifier : AsnElement
	{
		public string Value { get; }

		public AsnObjectIdentifier(ArraySegment<byte> data) : base(data)
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
	}

	public sealed class AsnBitString : AsnElement
	{
		public ArraySegment<byte> Value { get; }
		public int UnusedBits { get; }

		public AsnBitString(ArraySegment<byte> data) : base(data)
		{
			UnusedBits = data.Array[data.Offset];
			Value = new ArraySegment<byte>(data.Array, data.Offset + 1, data.Count - 1);
		}
	}

	public sealed class AsnOctetString : AsnElement
	{
		public ArraySegment<byte> Value { get; }

		public AsnOctetString(ArraySegment<byte> data) : base(data)
		{
			Value = data;
		}
	}

	public sealed class AsnNull : AsnElement
	{
		public AsnNull(ArraySegment<byte> data) : base(data)
		{
			if (data.Count > 0)
			{
				throw new InvalidOperationException("Null data cannot have a length.");
			}
		}

		public override string ToString() => "Null";
	}

	/// <summary>
	/// An asn.1 encoded boolean value.
	/// </summary>
	public sealed class AsnBoolean : AsnElement
	{
		/// <summary>
		/// The value of the asn element.
		/// </summary>
		public bool Value { get; }


		public AsnBoolean(ArraySegment<byte> data) : base(data)
		{
			for (var i = 0; i < data.Count; i++)
			{
				if (data.Array[data.Offset + i] > 0)
				{
					Value = true;
					return;
				}
			}
			Value = false;
		}

		public override string ToString() => Value.ToString();
	}

	public sealed class AsnRaw : AsnElement
	{
		public AsnTagType TagType { get; }
		
		public AsnRaw(AsnTagType tagType, ArraySegment<byte> data) : base(data)
		{
			TagType = tagType;
		}
	}

	public sealed class AsnSequence : AsnElement
	{
		public AsnSequence(ArraySegment<byte> data) : base(data)
		{
		}

		public IEnumerable<AsnElement> Elements()
		{
			var segment = Data;
			while (true)
			{
				if (segment.Count == 0)
				{
					yield break;
				}
				int elementLength;
				yield return AsnDecoder.Process(segment, out elementLength);
				segment = new ArraySegment<byte>(segment.Array, segment.Offset + elementLength, segment.Count - elementLength);
			}
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