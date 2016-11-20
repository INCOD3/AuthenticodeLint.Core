using System;

namespace AuthenticodeLint.Core.Asn
{

	/// <summary>
	/// An asn1 element. All elements inherit from this type.
	/// </summary>
	public abstract class AsnElement : IEquatable<AsnElement>
	{
		/// <summary>
		/// Gets the segement of data for the element.
		/// </summary>
		public ArraySegment<byte> Data { get; }

		/// <summary>
		/// The tag of the asn1 element.
		/// </summary>
		public AsnTagType Tag { get; }

		protected AsnElement(AsnTagType tag, ArraySegment<byte> data)
		{
			Data = data;
			Tag = tag;
		}

		public override bool Equals(object obj) => Equals(obj as AsnElement);

		public override int GetHashCode() => Data.GetHashCode();

		public virtual bool Equals(AsnElement other)
		{
			if (ReferenceEquals(other, null))
			{
				return false;
			}
			if (ReferenceEquals(this, other))
			{
				return true;
			}

			//They aren't for the same element type. False. We need to make sure
			//that two tags with the same binary representation (like 1 and "true")
			//aren't considered the same.
			if (Tag != other.Tag)
			{
				return false;
			}

			//If the segements lengths are different, we know it to be false.
			if (Data.Count != other.Data.Count)
			{
				return false;
			}

			//The counts are the same, and one of them is zero, so zero-length segements
			//should be equal to each other.
			if (Data.Count == 0)
			{
				return true;
			}

			//We can't check purely by offset since two elements might be the same
			//but duplicated in the segment.

			//If the underlying byte array has reference equality, and the count and offset
			//are the same, we can assume they are equal without a byte-for-byte comparison.
			//The previous check ensures we have the same count up to here.
			if (Data.Offset == other.Data.Offset && ReferenceEquals(Data, other.Data))
			{
				return true;
			}

			//We have the same count, but we have different offsets in to potentially different
			//arrays. We need to compare bytes. We might be able to vectorize this later.
			for (var i = 0; i < Data.Count; i++)
			{
				var position = Data.Offset + i;
				if (Data.Array[position] != other.Data.Array[position])
				{
					return false;
				}
			}
			//Byte comparison passed, return true.
			return true;
		}
	}

}