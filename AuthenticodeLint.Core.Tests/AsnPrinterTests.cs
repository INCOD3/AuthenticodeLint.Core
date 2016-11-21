using System;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
	public class AsnPrinterTests
	{
		[Fact]
		public void Garbage()
		{
			var data = System.IO.File.ReadAllBytes("files/vcsjones.com.crt");
			var decoded = AsnDecoder.Decode(data);
			AsnPrinter.Print(System.Console.Out, decoded);
		}
	}
}
