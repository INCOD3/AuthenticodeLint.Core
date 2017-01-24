using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AuthenticodeLint.Core
{
    public static class IncrementalHashExtensions
    {
        private static void WriteNativeBlock(IncrementalHash ih, IntPtr handle, int offset, int count)
        {
            var buffer = new byte[count];
            Marshal.Copy(handle + offset, buffer, 0, count);
            ih.AppendData(buffer);
        }

        public static void WriteStruct<T>(this IncrementalHash ih, T val) where T : struct
        {
            if (val.GetType().GetTypeInfo().IsAutoLayout)
            {
                throw new InvalidOperationException("Unable to write auto-layout struct.");
            }
            var size = Marshal.SizeOf<T>();
            var ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr<T>(val, ptr, false);
                Write(ih, ptr, 0, size);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public static void Write(this IncrementalHash ih, IntPtr ptr, int offset, int count, int bufferSize = 0x1000)
        {
            var address = ptr;
            if (count <= bufferSize)
            {
                WriteNativeBlock(ih, address, offset, count);
                return;
            }
            var blocks = count / bufferSize;
            var remainder = count % bufferSize;
            for (var i = 0; i < blocks; i++)
            {
                WriteNativeBlock(ih, address, offset + (i * bufferSize), bufferSize);
            }
            if (remainder != 0)
            {
                WriteNativeBlock(ih, address, offset + (blocks * bufferSize), remainder);
            }
        }

        public static void Write(this IncrementalHash ih, SafeHandle handle, int offset, int count)
        {
            bool handled = false;
            handle.DangerousAddRef(ref handled);
            if (!handled)
            {
                throw new InvalidOperationException("Unable to read native memory.");
            }
            var address = handle.DangerousGetHandle();
            try
            {
                Write(ih, address, offset, count);
            }
            finally
            {
                handle.DangerousRelease();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void AppendData(this IncrementalHash ih, ArraySegment<byte> data)
        {
            ih.AppendData(data.Array, data.Offset, data.Count);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ArraySegment<byte> GetSegmentHashAndReset(this IncrementalHash ih)
        {
            return new ArraySegment<byte>(ih.GetHashAndReset());
        }
    }
}