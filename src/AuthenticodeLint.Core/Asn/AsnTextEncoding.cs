using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    internal static class AsnTextEncoding
    {
        public static Encoding ASCII { get; } = Encoding.GetEncoding(
            Encoding.ASCII.CodePage,
            new EncoderExceptionFallback(),
            new DecoderExceptionFallback()
        );

        public static Encoding UTF8 { get; } = Encoding.GetEncoding(
            Encoding.UTF8.CodePage,
            new EncoderExceptionFallback(),
            new DecoderExceptionFallback()
        );

        public static Encoding BigEndianUnicode { get; } = Encoding.GetEncoding(
            Encoding.BigEndianUnicode.CodePage,
            new EncoderExceptionFallback(),
            new DecoderExceptionFallback()
        );
    }
}