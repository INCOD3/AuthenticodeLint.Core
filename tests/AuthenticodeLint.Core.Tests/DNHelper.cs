using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Tests
{
    /// <summary>
    /// This is a non-production quality encoder for testing the real decoder.
    /// The code is garbage.
    /// </summary>
    internal class DNHelper
    {
        public static AsnSequence TestDN(params Dictionary<string, string>[] dns)
        {
            List<byte[]> sets = new List<byte[]>();
            foreach (var dn in dns)
            {
                var set = new List<byte[]>();
                foreach (var component in dn)
                {
                    var seq = EncodeCollection(0x30, new byte[][]
                    {
                        EncodeObjectIdentifer(component.Key),
                        EncodePrintableString(component.Value)
                    });
                    set.Add(seq);
                }
                sets.Add(EncodeCollection(0x31, set.ToArray()));
            }
            var final = EncodeCollection(0x30, sets.ToArray());
            return (AsnSequence)AsnDecoder.Decode(final);
        }

        public static byte[] EncodeCollection(byte collectionType, byte[][] items)
        {
            using (var stream = new MemoryStream())
            {
                stream.WriteByte(collectionType);
                var length = items.Sum(i => i.Length);
                if (length > 0x7F)
                {
                    throw new NotImplementedException();
                }
                stream.WriteByte((byte)length);
                foreach (var item in items)
                {
                    stream.Write(item, 0, item.Length);
                }
                return stream.ToArray();
            }
        }

        public static byte[] EncodePrintableString(string str)
        {
            using (var stream = new MemoryStream())
            {
                stream.WriteByte(0x13); //PrintableString
                var strBytes = Encoding.ASCII.GetBytes(str);
                if (strBytes.Length > 0x7F)
                {
                    throw new NotImplementedException();
                }
                stream.WriteByte((byte)strBytes.Length);
                stream.Write(strBytes, 0, strBytes.Length);
                return stream.ToArray();
            }
        }

        public static byte[] EncodeObjectIdentifer(string oid)
        {
            var components = oid.Split('.').Select(long.Parse).ToArray();
            if (components.Length < 3)
            {
                throw new NotImplementedException();
            }
            using (var stream = new MemoryStream())
            {
                stream.WriteByte(0x06); //ObjectIdentifier
                var contents = new List<byte>();
                contents.Add(checked((byte)(components[0] * 40 + components[1])));
                for (var i = 2; i < components.Length; i++)
                {
                    var component = components[i];
                    if (component < 0x7F)
                    {
                        contents.Add((byte)component);
                    }
                    else
                    {
                        var copy = component;
                        while (copy > 0x7F)
                        {
                            var octet = 0x80 | (copy & 0x7F);
                            contents.Add((byte)octet);
                            copy >>= 7;
                        }
                        contents.Add((byte)copy);
                    }
                }
                stream.WriteByte((byte)contents.Count);
                stream.Write(contents.ToArray(), 0, contents.Count);
                return stream.ToArray();
            }
        }
    }
}
