using System.IO;

namespace AuthenticodeLint.Core.Asn
{
    public static class AsnPrinter
    {
        public static void Print(TextWriter writer, AsnElement element) => Print(writer, element, 0);

        private static void Print(TextWriter writer, AsnElement element, int level)
        {
            var indent = level == 0 ? string.Empty : new string(' ', level * 2);
            var displayTag = DisplayTag(element.Tag);
            writer.Write(indent);
            writer.Write(displayTag);
            switch (element)
            {
                case AsnConstructed c:
                    writer.WriteLine(':');
                    foreach (var child in c)
                    {
                        Print(writer, child, level + 1);
                    }
                    break;
                default:
                    writer.Write(": ");
                    writer.WriteLine(element);
                    break;
            }
        }

        private static string DisplayTag(AsnTag tag) => tag.AsnClass == AsnClass.Univeral ? tag.Tag.ToString() : $"[{((ulong)tag.Tag)}]";
    }
}
