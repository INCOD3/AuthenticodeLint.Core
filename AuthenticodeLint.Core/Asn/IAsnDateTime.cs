using System;
namespace AuthenticodeLint.Core.Asn
{
	public interface IAsnDateTime
	{
		DateTimeOffset Value { get; }
	}
}
