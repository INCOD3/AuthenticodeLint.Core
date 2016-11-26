namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// Any asn.1 element that is a "Directory String". That is, is a printable string value.
    /// </summary>
    public interface IDirectoryString : IAsnElement
    {
        string Value { get; }
    }
}
