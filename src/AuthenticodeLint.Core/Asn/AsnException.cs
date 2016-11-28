using System;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnException : Exception
    {
        public AsnException(string message) : base(message)
        {
        }

        public AsnException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}