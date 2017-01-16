using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace AuthenticodeLint.Core
{
    internal static class StreamExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Write(this Stream stream, ArraySegment<byte> segment)
        {
            stream.Write(segment.Array, segment.Offset, segment.Count);
        }
    }
}