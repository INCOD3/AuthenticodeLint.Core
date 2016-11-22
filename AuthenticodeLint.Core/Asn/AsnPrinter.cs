using System.IO;

namespace AuthenticodeLint.Core.Asn
{
	public static class AsnPrinter
	{
		public static void Print(TextWriter writer, AsnElement element) => Print(writer, element, 0);

		private static void Print(TextWriter writer, AsnElement element, int level)
		{
			var indent = level == 0 ? string.Empty : new string(' ', level * 2);
			var asConstructed = element as AsnConstructed;
			var displayTag = DisplayTag(element.Tag);
			if (asConstructed != null)
			{
				writer.WriteLine($"{indent}{displayTag}:");
				var sequence = (AsnConstructed)element;
				foreach (var child in sequence)
				{
					Print(writer, child, level + 1);
				}
			}
			else
			{
				writer.WriteLine($"{indent}{displayTag}: {element.ToString()}");
			}
		}

		private static string DisplayTag(AsnTag tag)
		{
			if (tag.AsnClass == AsnClass.Univeral)
			{
				return tag.Tag.ToString();
			}
			return $"[{((byte)tag.Tag)}]";
		}
	}
}
