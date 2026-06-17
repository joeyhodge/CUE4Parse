using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using CUE4Parse.UE4.Objects.Core.Misc;
using CUE4Parse.UE4.VirtualFileSystem;
using Serilog;

namespace CUE4Parse.GameTypes.ProSpi.Encryption.Aes;

public static class ProSpiAes
{
    public const int EncryptedBlockTrailerSize = 0x18;

    private const uint ProcessCreateThread = 0x0002;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint MemCommit = 0x1000;
    private const uint MemReserve = 0x2000;
    private const uint MemRelease = 0x8000;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint WaitObject0 = 0x00000000;
    private const uint WaitTimeout = 0x00000102;

    private const long ProSpi24DecryptDataRva = 0x46F6DC0;
    private static readonly (string Build, long Rva)[] ProSpiDecryptBuilds =
    {
        ("eBaseball PRO SPIRIT 2.1.0", 0x4954460),
        ("eBaseball PRO SPIRIT", 0x46D2F80),
        ("Professional Baseball Spirits 2024-2025", 0x4713DA0)
    };
    private const int RemoteCallTimeoutMs = 15_000;
    private static readonly byte[] DecryptDataEntrySignature =
    {
        0x40, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00
    };

    private static readonly ILogger Log = Serilog.Log.ForContext(typeof(ProSpiAes));
    private static readonly object BridgeLock = new();
    private static IntPtr _processHandle;
    private static int _processId;
    private static long _moduleBase;
    private static long _decryptDataRva;
    private static string? _projectRoot;
    private static string? _decryptBuild;

    public static bool IsProSpiArchive(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var normalized = NormalizePath(path);

        // Match the Unreal project-relative layout, independent of Steam library or drive.
        var paksMarker = $"{Path.DirectorySeparatorChar}prospi{Path.DirectorySeparatorChar}Content{Path.DirectorySeparatorChar}Paks";
        return normalized.Contains(paksMarker + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(paksMarker, StringComparison.OrdinalIgnoreCase);
    }

    public static byte[] ProSpiDecrypt(byte[] bytes, int beginOffset, int count, bool isIndex, IAesVfsReader reader)
    {
        if (bytes.Length < beginOffset + count)
            throw new IndexOutOfRangeException("beginOffset + count is larger than the length of bytes");
        if (count % 16 != 0)
            throw new ArgumentException("count must be a multiple of 16");

        var input = new byte[count];
        Buffer.BlockCopy(bytes, beginOffset, input, 0, count);

        lock (BridgeLock)
        {
            EnsureBridge(reader.Path);
            return RemoteDecrypt(input, reader.EncryptionKeyGuid);
        }
    }

    private static void EnsureBridge(string archivePath)
    {
        var requestedProjectRoot = GetProjectRoot(archivePath, "Content", "Paks");
        if (_processHandle != IntPtr.Zero &&
            IsProcessStillRunning(_processId) &&
            (requestedProjectRoot == null ||
             requestedProjectRoot.Equals(_projectRoot, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        ResetBridge();

        using var process = FindProSpiProcess(requestedProjectRoot) ?? throw new InvalidOperationException(
            "ProSpi custom decryption requires prospi-Win64-Shipping.exe or prospi24-Win64-Shipping.exe to be running.");

        var handle = OpenProcess(
            ProcessCreateThread | ProcessQueryInformation | ProcessVmOperation | ProcessVmRead | ProcessVmWrite,
            false,
            process.Id);
        if (handle == IntPtr.Zero)
            throw new InvalidOperationException($"OpenProcess failed for {process.ProcessName} ({process.Id}): {Marshal.GetLastWin32Error()}");

        try
        {
            var mainModule = process.MainModule ?? throw new InvalidOperationException($"Could not read main module for {process.ProcessName} ({process.Id}).");
            var moduleBase = mainModule.BaseAddress.ToInt64();
            var (build, decryptDataRva) = ResolveDecryptDataEntry(handle, moduleBase, process.ProcessName);

            _processHandle = handle;
            _processId = process.Id;
            _moduleBase = moduleBase;
            _decryptDataRva = decryptDataRva;
            _projectRoot = GetProjectRoot(mainModule.FileName, "Binaries", "Win64") ?? requestedProjectRoot;
            _decryptBuild = build;
        }
        catch
        {
            CloseHandle(handle);
            throw;
        }

        Log.Information(
            "ProSpi live decrypt bridge attached to {Build} via {ProcessName} ({ProcessId}) at 0x{ModuleBase:X}, DecryptData RVA 0x{DecryptDataRva:X}",
            _decryptBuild, process.ProcessName, _processId, _moduleBase, _decryptDataRva);
    }

    private static Process? FindProSpiProcess(string? requestedProjectRoot)
    {
        var fallbacks = new List<Process>();

        foreach (var processName in new[] { "prospi-Win64-Shipping", "prospi24-Win64-Shipping" })
        {
            foreach (var process in Process.GetProcessesByName(processName))
            {
                try
                {
                    var mainModule = process.MainModule;
                    var processProjectRoot = mainModule == null
                        ? null
                        : GetProjectRoot(mainModule.FileName, "Binaries", "Win64");

                    if (requestedProjectRoot != null &&
                        processProjectRoot != null &&
                        requestedProjectRoot.Equals(processProjectRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var fallback in fallbacks)
                            fallback.Dispose();
                        return process;
                    }

                    fallbacks.Add(process);
                }
                catch
                {
                    process.Dispose();
                }
            }
        }

        if (requestedProjectRoot == null && fallbacks.Count == 1)
            return fallbacks[0];

        foreach (var fallback in fallbacks)
            fallback.Dispose();

        if (fallbacks.Count > 0)
        {
            throw new InvalidOperationException(
                $"Found {fallbacks.Count} running ProSpi processes, but none matched archive root '{requestedProjectRoot}'. " +
                "Close the unrelated game or open archives from the matching installation.");
        }

        return null;
    }

    private static bool IsProcessStillRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] RemoteDecrypt(byte[] input, FGuid guid)
    {
        var codeOffset = Align(input.Length + FGuid.Size, 16);
        var allocationSize = codeOffset + 64;
        var allocation = VirtualAllocEx(_processHandle, IntPtr.Zero, (UIntPtr) allocationSize, MemCommit | MemReserve, PageExecuteReadWrite);
        if (allocation == IntPtr.Zero)
            throw new InvalidOperationException($"VirtualAllocEx failed for ProSpi decrypt bridge: {Marshal.GetLastWin32Error()}");

        try
        {
            var remoteBuffer = allocation;
            var remoteGuid = IntPtr.Add(allocation, input.Length);
            var remoteCode = IntPtr.Add(allocation, codeOffset);
            var decryptAddress = _moduleBase + _decryptDataRva;
            var code = BuildShellcode(remoteBuffer, input.Length, remoteGuid, decryptAddress);
            var guidBytes = guid.AsByteSpan().ToArray();

            WriteRemote(remoteBuffer, input, "encrypted payload");
            WriteRemote(remoteGuid, guidBytes, "encryption key guid");
            WriteRemote(remoteCode, code, "decrypt bridge code");

            var thread = CreateRemoteThread(_processHandle, IntPtr.Zero, 0, remoteCode, IntPtr.Zero, 0, out _);
            if (thread == IntPtr.Zero)
                throw new InvalidOperationException($"CreateRemoteThread failed for ProSpi decrypt bridge: {Marshal.GetLastWin32Error()}");

            try
            {
                var wait = WaitForSingleObject(thread, RemoteCallTimeoutMs);
                if (wait == WaitTimeout)
                    throw new TimeoutException("Timed out waiting for ProSpi decrypt bridge.");
                if (wait != WaitObject0)
                    throw new InvalidOperationException($"ProSpi decrypt bridge wait failed: 0x{wait:X8}");
            }
            finally
            {
                CloseHandle(thread);
            }

            var output = new byte[input.Length];
            if (!ReadProcessMemory(_processHandle, remoteBuffer, output, output.Length, out var bytesRead) ||
                bytesRead.ToInt64() != output.Length)
            {
                throw new InvalidOperationException($"ReadProcessMemory failed for ProSpi decrypted payload: {Marshal.GetLastWin32Error()}");
            }

            return output;
        }
        finally
        {
            VirtualFreeEx(_processHandle, allocation, UIntPtr.Zero, MemRelease);
        }
    }

    private static (string Build, long Rva) ResolveDecryptDataEntry(IntPtr processHandle, long moduleBase, string processName)
    {
        (string Build, long Rva)[] candidates = processName.Equals("prospi24-Win64-Shipping", StringComparison.OrdinalIgnoreCase)
            ? new[] { (Build: "Professional Baseball Spirits 2024-2025 (prospi24)", Rva: ProSpi24DecryptDataRva) }
            : ProSpiDecryptBuilds;
        var matches = new List<(string Build, long Rva)>();

        foreach (var candidate in candidates)
        {
            var address = new IntPtr(moduleBase + candidate.Rva);
            var actual = new byte[DecryptDataEntrySignature.Length];
            if (ReadProcessMemory(processHandle, address, actual, actual.Length, out var bytesRead) &&
                bytesRead.ToInt64() == actual.Length &&
                actual.AsSpan().SequenceEqual(DecryptDataEntrySignature))
            {
                matches.Add(candidate);
            }
        }

        if (matches.Count == 1)
            return matches[0];

        var candidateRvas = string.Join(", ", Array.ConvertAll(candidates, candidate => $"0x{candidate.Rva:X}"));
        var reason = matches.Count == 0
            ? "none of the known entries matched"
            : "more than one known entry matched";
        throw new InvalidOperationException(
            $"Could not identify the ProSpi build for {processName}: {reason} ({candidateRvas}). " +
            "Refusing to run the live decrypt bridge.");
    }

    private static string NormalizePath(string path)
    {
        try
        {
            return Path.GetFullPath(path)
                .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)
                .TrimEnd(Path.DirectorySeparatorChar);
        }
        catch
        {
            return path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)
                .TrimEnd(Path.DirectorySeparatorChar);
        }
    }

    private static string? GetProjectRoot(string? path, string directory, string childDirectory)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        var normalized = NormalizePath(path);
        var marker = $"{Path.DirectorySeparatorChar}{directory}{Path.DirectorySeparatorChar}{childDirectory}";
        var markerIndex = normalized.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        return markerIndex <= 0 ? null : normalized[..markerIndex];
    }

    private static void ResetBridge()
    {
        if (_processHandle != IntPtr.Zero)
            CloseHandle(_processHandle);

        _processHandle = IntPtr.Zero;
        _processId = 0;
        _moduleBase = 0;
        _decryptDataRva = 0;
        _projectRoot = null;
        _decryptBuild = null;
    }

    private static void WriteRemote(IntPtr address, byte[] data, string description)
    {
        if (!WriteProcessMemory(_processHandle, address, data, data.Length, out var bytesWritten) ||
            bytesWritten.ToInt64() != data.Length)
        {
            throw new InvalidOperationException($"WriteProcessMemory failed for ProSpi {description}: {Marshal.GetLastWin32Error()}");
        }
    }

    private static byte[] BuildShellcode(IntPtr buffer, int count, IntPtr guid, long decryptAddress)
    {
        var code = new byte[48];
        var offset = 0;

        Emit(code, ref offset, 0x48, 0x83, 0xEC, 0x28); // sub rsp, 28h
        Emit(code, ref offset, 0x48, 0xB9);             // mov rcx, buffer
        EmitUInt64(code, ref offset, (ulong) buffer.ToInt64());
        Emit(code, ref offset, 0xBA);                   // mov edx, count
        EmitUInt32(code, ref offset, (uint) count);
        Emit(code, ref offset, 0x49, 0xB8);             // mov r8, guid
        EmitUInt64(code, ref offset, (ulong) guid.ToInt64());
        Emit(code, ref offset, 0x48, 0xB8);             // mov rax, DecryptData
        EmitUInt64(code, ref offset, (ulong) decryptAddress);
        Emit(code, ref offset, 0xFF, 0xD0);             // call rax
        Emit(code, ref offset, 0x48, 0x83, 0xC4, 0x28); // add rsp, 28h
        Emit(code, ref offset, 0xC3);                   // ret

        Array.Resize(ref code, offset);
        return code;
    }

    private static int Align(int value, int alignment) => (value + alignment - 1) & ~(alignment - 1);

    private static void Emit(byte[] destination, ref int offset, params byte[] bytes)
    {
        bytes.CopyTo(destination, offset);
        offset += bytes.Length;
    }

    private static void EmitUInt32(byte[] destination, ref int offset, uint value)
    {
        BitConverter.GetBytes(value).CopyTo(destination, offset);
        offset += sizeof(uint);
    }

    private static void EmitUInt64(byte[] destination, ref int offset, ulong value)
    {
        BitConverter.GetBytes(value).CopyTo(destination, offset);
        offset += sizeof(ulong);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
}
