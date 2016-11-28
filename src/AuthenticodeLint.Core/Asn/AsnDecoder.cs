using System;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// Decodes asn1 encoded data.
    /// </summary>
    public static class AsnDecoder
    {
        public static AsnElement Decode(byte[] asnData) => Decode(new ArraySegment<byte>(asnData));

        public static AsnElement Decode(ArraySegment<byte> data)
        {
            int octetLength, tagLength;
            var tag = ReadTag(data, out tagLength);
            var lengthWindow = data.Advance(tagLength);
            var length = ReadTagLength(lengthWindow, out octetLength);
            var contentData = new ArraySegment<byte>(lengthWindow.Array, lengthWindow.Offset + octetLength, (int)length);
            var elementLength = tagLength + octetLength + checked((int)length);
            var elementData = new ArraySegment<byte>(data.Array, data.Offset, elementLength);
            if (tag.AsnClass == AsnClass.Univeral)
            {
                switch (tag.Tag)
                {
                    case AsnTagValue.Integer:
                        return new AsnInteger(tag, contentData, elementData);
                    case AsnTagValue.Boolean:
                        return new AsnBoolean(tag, contentData, elementData);
                    case AsnTagValue.BitString:
                        return new AsnBitString(tag, contentData, elementData);
                    case AsnTagValue.OctetString:
                        return new AsnOctetString(tag, contentData, elementData);
                    case AsnTagValue.ObjectIdentifier:
                        return new AsnObjectIdentifier(tag, contentData, elementData);
                    case AsnTagValue.IA5String:
                        return new AsnIA5String(tag, contentData, elementData);
                    case AsnTagValue.AsnNull:
                        return new AsnNull(tag, contentData, elementData);
                    case AsnTagValue.SequenceSequenceOf:
                        return new AsnSequence(tag, contentData, elementData);
                    case AsnTagValue.SetSetOf:
                        return new AsnSet(tag, contentData, elementData);
                    case AsnTagValue.PrintableString:
                        return new AsnPrintableString(tag, contentData, elementData);
                    case AsnTagValue.UtcTime:
                        return new AsnUtcTime(tag, contentData, elementData);
                    case AsnTagValue.GeneralizedTime:
                        return new AsnGeneralizedTime(tag, contentData, elementData);
                    case AsnTagValue.NumericString:
                        return new AsnNumericString(tag, contentData, elementData);
                    case AsnTagValue.BmpString:
                        return new AsnBmpString(tag, contentData, elementData);
                }
            }
            if (tag.Constructed)
            {
                return new AsnConstructed(tag, contentData, elementData);
            }
            else
            {
                return new AsnRaw(tag, contentData, elementData);
            }
        }

        private static AsnTag ReadTag(ArraySegment<byte> tagData, out int tagLength)
        {
            var tag = tagData.Array[tagData.Offset];
            var asnClass = (AsnClass)((tag & 0xC0) >> 6);
            var constructed = (tag & 0x20) == 0x20;
            var highTagNumber = (tag & 0x1F) == 0x1F; //5 lower bits set
            if (!highTagNumber)
            {
                tagLength = 1;
                return new AsnTag((AsnTagValue)(tag & 0x1F), asnClass, constructed);
            }
            else
            {
                ulong tagNumber = 0;
                for (var i = 1; i < tagData.Count; i++)
                {
                    if (i > 8)
                    {
                        throw new AsnException($"asn.1 encoded tag is larger than the supported maximum of {ulong.MaxValue}");
                    }
                    var item = tagData.Array[tagData.Offset + i];
                    tagNumber <<= 7;
                    tagNumber |= (byte)(item & 0x7F);
                    if ((item & 0x80) != 0x80)
                    {
                        tagLength = i + 1;
                        return new AsnTag((AsnTagValue)tagNumber, asnClass, constructed);
                    }
                }
                throw new AsnException("asn.1 tag malformed. Expected more data.");
            }
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

    //This enum is a ulong because other non-universal values
    //may be converted to this enum as a nameless value. 
    public enum AsnTagValue : ulong
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