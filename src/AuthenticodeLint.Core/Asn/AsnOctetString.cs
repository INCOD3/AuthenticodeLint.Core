using System;

namespace AuthenticodeLint.Core.Asn
{

    public sealed class AsnOctetString : AsnElement
    {
        public ArraySegment<byte> Value => ContentData;

        public AsnOctetString(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
        }
    }

}