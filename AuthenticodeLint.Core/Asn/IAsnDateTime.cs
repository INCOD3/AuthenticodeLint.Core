using System;
namespace AuthenticodeLint.Core.Asn
{
    public interface IAsnDateTime : IAsnElement
    {
        DateTimeOffset Value { get; }
    }
}
