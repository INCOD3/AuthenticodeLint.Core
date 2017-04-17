using System;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// Decodes asn1 encoded data.
    /// </summary>
    public static class AsnDecoder
    {
        public static AsnElement Decode(byte[] asnData) => Decode(new ArraySegment<byte>(asnData));

        public static bool TryDecode(byte[] asnData, out AsnElement element)
        {
            try
            {
                element = Decode(asnData);
                return true;
            }
            catch (AsnException)
            {
                element = default(AsnElement);
                return false;
            }
        }

        public static bool TryDecode(ArraySegment<byte> asnData, out AsnElement element)
        {
            try
            {
                element = Decode(asnData);
                return true;
            }
            catch (AsnException)
            {
                element = default(AsnElement);
                return false;
            }
        }

        public static AsnElement Decode(ArraySegment<byte> data)
        {
            var (tag, tagLength) = ReadTag(data);
            var lengthWindow = data.Advance(tagLength);
            var (contentLength, octetLength) = ReadTagLength(lengthWindow);
            var allLength = lengthWindow.Array.Length - lengthWindow.Offset - octetLength;
            var contentData = new ArraySegment<byte>(lengthWindow.Array, lengthWindow.Offset + octetLength, allLength);
            var elementLength = tagLength + octetLength + allLength;
            var nonContentHeaderSize = tagLength + octetLength;
            var elementData = new ArraySegment<byte>(data.Array, data.Offset, elementLength);
            if (tag.AsnClass == AsnClass.Univeral)
            {
                switch (tag.Tag)
                {
                    case AsnTagValue.Integer:
                        return new AsnInteger(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.Boolean:
                        return new AsnBoolean(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.BitString:
                        return new AsnBitString(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.OctetString:
                        return new AsnOctetString(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.ObjectIdentifier:
                        return new AsnObjectIdentifier(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.IA5String:
                        return new AsnIA5String(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.AsnNull:
                        return new AsnNull(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.SequenceSequenceOf:
                        return new AsnSequence(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.SetSetOf:
                        return new AsnSet(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.PrintableString:
                        return new AsnPrintableString(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.UtcTime:
                        return new AsnUtcTime(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.GeneralizedTime:
                        return new AsnGeneralizedTime(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.NumericString:
                        return new AsnNumericString(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.BmpString:
                        return new AsnBmpString(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.Utf8String:
                        return new AsnUtf8String(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                    case AsnTagValue.VisibleStringIso646String:
                        return new AsnVisibleString(tag, contentData, elementData, contentLength, nonContentHeaderSize);
                }
            }
            if (tag.Constructed)
            {
                return new AsnConstructed(tag, contentData, elementData, contentLength, nonContentHeaderSize);
            }
            else
            {
                return new AsnRaw(tag, contentData, elementData, contentLength, nonContentHeaderSize);
            }
        }

        private static (AsnTag, int) ReadTag(ArraySegment<byte> tagData)
        {
            var tag = tagData.Array[tagData.Offset];
            var asnClass = (AsnClass)((tag & 0xC0) >> 6);
            var constructed = (tag & 0x20) == 0x20;
            var highTagNumber = (tag & 0x1F) == 0x1F; //5 lower bits set
            if (!highTagNumber)
            {
                return (new AsnTag((AsnTagValue)(tag & 0x1F), asnClass, constructed), 1);
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
                        return (new AsnTag((AsnTagValue)tagNumber, asnClass, constructed), i + 1);
                    }
                }
                throw new AsnException("asn.1 tag malformed. Expected more data.");
            }
        }

        private static (ulong? tag, int length) ReadTagLength(ArraySegment<byte> data)
        {
            var firstByte = data.Array[data.Offset];
            if (firstByte == 0x80)
            {
                return (null, 1);
            }
            var isLongForm = (firstByte & 0x80) == 0x80;
            if (!isLongForm)
            {
                return (firstByte, 1);
            }
            int length = firstByte & 0x7F;
            var octetLength = length + 1;
            ulong value = 0;
            for (var i = 0; i < length; i++)
            {
                value <<= 8;
                value |= data.Array[data.Offset + 1 + i];
            }
            return (value, octetLength);
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