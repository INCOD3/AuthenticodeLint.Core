using System;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class Pkcs7Exception : Exception
    {
        public Pkcs7Exception(string message)
            : base(message)
        {
        }

        public Pkcs7Exception(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}