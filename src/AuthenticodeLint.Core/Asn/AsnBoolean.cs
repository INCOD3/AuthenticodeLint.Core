using System;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// An asn.1 encoded boolean value.
    /// </summary>
    public sealed class AsnBoolean : AsnElement
    {
        /// <summary>
        /// The value of the asn element.
        /// </summary>
        public bool Value { get; }

        public AsnBoolean(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
            if (contentData.Count == 0)
            {
                throw new AsnException("asn.1 boolean value cannot be empty.");
            }
            for (var i = 0; i < contentData.Count; i++)
            {
                if (contentData.Array[contentData.Offset + i] > 0)
                {
                    Value = true;
                    return;
                }
            }
            Value = false;
        }

        public override string ToString() => Value.ToString();

        public override bool Equals(AsnElement other)
        {
            //"True" can be respresented as any non-zero value. For the sake of boolean, we want to allow "true"
            //to always equal true, regardless of how it was encoded.
            var boolean = other as AsnBoolean;
            if (boolean == null)
            {
                return base.Equals(other);
            }
            return boolean.Value == Value;
        }
    }
}