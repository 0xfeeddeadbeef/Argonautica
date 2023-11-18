// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Argonautica;

/// <summary>
///   Ensures that a given span does not refer to <see langword="null"/>.
/// </summary>
/// <see href="https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/Helpers.cs"/>
internal static class SpanHelpers
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static unsafe ref readonly byte GetNonNullPinnableReference(ReadOnlySpan<byte> buffer)
    {
        // Based on the internal implementation from MemoryMarshal.
        return ref buffer.Length != 0 ? ref MemoryMarshal.GetReference(buffer) : ref Unsafe.AsRef<byte>((void*)1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static unsafe ref byte GetNonNullPinnableReference(Span<byte> buffer)
    {
        // Based on the internal implementation from MemoryMarshal.
        return ref buffer.Length != 0 ? ref MemoryMarshal.GetReference(buffer) : ref Unsafe.AsRef<byte>((void*)1);
    }
}
