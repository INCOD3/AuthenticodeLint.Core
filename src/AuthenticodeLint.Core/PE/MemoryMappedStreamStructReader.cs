using System;
using System.IO.MemoryMappedFiles;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;


namespace AuthenticodeLint.Core.PE
{
    /// <summary>
    /// Reads a struct from a memory mapped view region. This will
    /// can possibly be removed when netstandard 2.0 is available.
    /// </summary>
    internal static class MemoryMappedStreamStructReader
    {
        public static T ReadStruct<T>(this MemoryMappedViewAccessor va, int offset = 0) where T : struct
        {
            var type = typeof(T);
            var typeInfo = type.GetTypeInfo();
            if (!typeInfo.IsLayoutSequential)
            {
                throw new InvalidOperationException("Type must have a sequential layout.");
            }
            var handle = va.SafeMemoryMappedViewHandle;
            var inc = false;
            handle.DangerousAddRef(ref inc);
            if (!inc)
            {
                throw new InvalidOperationException("Could not increment reference.");
            }
            try
            {
                return Marshal.PtrToStructure<T>(handle.DangerousGetHandle() + offset);
            }
            finally
            {
                handle.DangerousRelease();
            }
        }

        public static T[] ReadStructArray<T>(this MemoryMappedViewAccessor va, int count, int offset = 0) where T : struct
        {
            var type = typeof(T);
            var typeInfo = type.GetTypeInfo();
            if (!typeInfo.IsLayoutSequential)
            {
                throw new InvalidOperationException("Type must have a sequential layout.");
            }
            var handle = va.SafeMemoryMappedViewHandle;
            var inc = false;
            handle.DangerousAddRef(ref inc);
            if (!inc)
            {
                throw new InvalidOperationException("Could not increment reference.");
            }
            try
            {
                var ptr = handle.DangerousGetHandle();
                var size = Marshal.SizeOf<T>();
                var buffer = new T[count];
                for(var i = 0; i < count; i++)
                {
                    buffer[i] = Marshal.PtrToStructure<T>(ptr + offset + (i * size));
                }
                return buffer;
            }
            finally
            {
                handle.DangerousRelease();
            }
        }

        public static async Task<T> ReadStructAsync<T>(this MemoryMappedViewStream stream, int offset = 0) where T : struct
        {
            var type = typeof(T);
            var typeInfo = type.GetTypeInfo();
            if (!typeInfo.IsLayoutSequential)
            {
                throw new InvalidOperationException("Type must have a sequential layout.");
            }
            var size = Marshal.SizeOf<T>();
            var allocation = new byte[size];
            var read = await stream.ReadAsync(allocation, offset, size);
            if (read != size)
            {
                throw new InvalidOperationException("Reached the end of the stream.");
            }
            var pin = GCHandle.Alloc(allocation, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<T>(pin.AddrOfPinnedObject());
            }
            finally
            {
                pin.Free();
            }
        }

        /// <summary>
        /// Reads an array of structures from a memory mapped stream.
        /// </summary>
        public static async Task<T[]> ReadStructArrayAsync<T>(this MemoryMappedViewStream stream, int count, int offset = 0) where T : struct
        {
            var type = typeof(T);
            var typeInfo = type.GetTypeInfo();
            if (!typeInfo.IsLayoutSequential)
            {
                throw new InvalidOperationException("Type must have a sequential layout.");
            }
            var arr = new T[count];
            var size = Marshal.SizeOf<T>();
            var allocation = new byte[size];
            var pin = GCHandle.Alloc(allocation, GCHandleType.Pinned);
            var pinAddress = pin.AddrOfPinnedObject();
            try
            {
                for (var i = 0; i < count; i++)
                {
                    var read = await stream.ReadAsync(allocation, offset, size);
                    if (read != size)
                    {
                        throw new InvalidOperationException("Reached the end of the stream.");
                    }
                    arr[i] = Marshal.PtrToStructure<T>(pinAddress);
                }
            }
            finally
            {
                pin.Free();
            }
            return arr;
        }
    }
}