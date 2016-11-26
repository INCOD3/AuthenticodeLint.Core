using System;
namespace AuthenticodeLint.Core.x509
{
    public sealed class x509Exception : Exception
    {
        public x509Exception(string message) : base(message)
        {
        }
    }
}