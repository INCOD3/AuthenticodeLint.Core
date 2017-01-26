using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace AuthenticodeLint.Core
{
    public static class StreamExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Write(this Stream stream, ArraySegment<byte> segment)
        {
            stream.Write(segment.Array, segment.Offset, segment.Count);
        }

        public static async Task CopyUpToAsync(this Stream src, Stream destination, long upTo, int bufferSize = 0x4000)
        {
            var buffer = new byte[bufferSize];
            var totalWritten = 0L;
            int read;
            while((read = await src.ReadAsync(buffer, 0, buffer.Length)) != 0 && totalWritten < upTo)
            {
                var amountToWrite = checked((int)Math.Min(upTo - totalWritten, read));
                await destination.WriteAsync(buffer, 0, amountToWrite);
                totalWritten += read;
            }
        }
    }
}