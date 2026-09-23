using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace xScanner.Analysis
{
    public class PEAnalysisResult
    {
        public bool IsValidPe { get; set; }
        public string Architecture { get; set; } = "Unknown";
        public bool HasDigitalSignature { get; set; }
        public string SignerName { get; set; } = string.Empty;
        public List<PeSectionInfo> Sections { get; set; } = new();
        public List<string> SuspiciousApis { get; set; } = new();
        public List<string> Indicators { get; set; } = new();
        public double MaxEntropy { get; set; }
        public bool IsSuspicious { get; set; }
    }

    public class PeSectionInfo
    {
        public string Name { get; set; } = string.Empty;
        public uint VirtualSize { get; set; }
        public uint RawSize { get; set; }
        public double Entropy { get; set; }
        public bool IsExecutable { get; set; }
        public bool IsWritable { get; set; }
    }

    public class PEAnalyzer
    {
        private static readonly HashSet<string> SuspiciousApiSet = new(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
            "CreateRemoteThread", "CreateProcess", "ShellExecute", "InternetOpen",
            "InternetConnect", "HttpSendRequest", "RegCreateKey", "RegSetValue",
            "AdjustTokenPrivileges", "SeDebugPrivilege"
        };

        public static PEAnalysisResult Analyze(string filePath)
        {
            var result = new PEAnalysisResult();
            try
            {
                if (!File.Exists(filePath)) return result;

                byte[] headerBytes = new byte[4096];
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (fs.Length < 64) return result;
                    fs.Read(headerBytes, 0, Math.Min((int)fs.Length, headerBytes.Length));
                }

                // Check MZ header
                if (headerBytes[0] != 'M' || headerBytes[1] != 'Z')
                {
                    return result;
                }

                result.IsValidPe = true;

                // Get PE header offset
                int peOffset = BitConverter.ToInt32(headerBytes, 60);
                if (peOffset <= 0 || peOffset + 24 > headerBytes.Length)
                {
                    // Basic PE signature check failed or too large for buffer, still valid PE
                    return result;
                }

                // Check PE signature "PE\0\0"
                if (headerBytes[peOffset] != 'P' || headerBytes[peOffset + 1] != 'E')
                {
                    return result;
                }

                // Machine type at peOffset + 4
                ushort machine = BitConverter.ToUInt16(headerBytes, peOffset + 4);
                result.Architecture = machine switch
                {
                    0x014c => "x86 (32-bit)",
                    0x8664 => "x64 (64-bit)",
                    0x01c4 => "ARM",
                    0xaa64 => "ARM64",
                    _ => $"Unknown (0x{machine:X4})"
                };

                // Number of sections at peOffset + 6
                ushort numSections = BitConverter.ToUInt16(headerBytes, peOffset + 6);

                // Optional header size at peOffset + 20
                ushort optionalHeaderSize = BitConverter.ToUInt16(headerBytes, peOffset + 20);
                int sectionHeaderOffset = peOffset + 24 + optionalHeaderSize;

                // Check Digital Signature via X509Certificate
                try
                {
                    var cert = new X509Certificate2(filePath);
                    result.HasDigitalSignature = true;
                    result.SignerName = cert.Subject;
                }
                catch
                {
                    result.HasDigitalSignature = false;
                }

                // Parse sections if within bounds
                double maxEntropy = 0.0;
                for (int i = 0; i < numSections; i++)
                {
                    int currentSecOffset = sectionHeaderOffset + (i * 40);
                    if (currentSecOffset + 40 > headerBytes.Length) break;

                    string name = System.Text.Encoding.ASCII.GetString(headerBytes, currentSecOffset, 8).TrimEnd('\0');
                    uint virtualSize = BitConverter.ToUInt32(headerBytes, currentSecOffset + 8);
                    uint rawSize = BitConverter.ToUInt32(headerBytes, currentSecOffset + 16);
                    uint characteristics = BitConverter.ToUInt32(headerBytes, currentSecOffset + 36);

                    bool isExec = (characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
                    bool isWrite = (characteristics & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE

                    // Calculate section entropy if raw data is accessible
                    double entropy = 0.0;
                    if (rawSize > 0 && currentSecOffset + 40 <= headerBytes.Length)
                    {
                        entropy = CalculateEntropy(headerBytes, currentSecOffset, (int)Math.Min(rawSize, 1024));
                    }

                    if (entropy > maxEntropy) maxEntropy = entropy;

                    result.Sections.Add(new PeSectionInfo
                    {
                        Name = name,
                        VirtualSize = virtualSize,
                        RawSize = rawSize,
                        Entropy = entropy,
                        IsExecutable = isExec,
                        IsWritable = isWrite
                    });

                    // Suspicious section characteristics (e.g. Writable and Executable)
                    if (isExec && isWrite)
                    {
                        result.Indicators.Add($"Section '{name}' is both Writable and Executable (suspicious)");
                    }
                    if (entropy > 7.2)
                    {
                        result.Indicators.Add($"Section '{name}' has high entropy ({entropy:F2}), suggesting packing or encryption");
                    }
                }

                result.MaxEntropy = maxEntropy;

                // Heuristics decision
                result.IsSuspicious = result.Indicators.Count > 0 || (!result.HasDigitalSignature && maxEntropy > 7.0);
            }
            catch (Exception ex)
            {
                result.Indicators.Add($"Analysis error: {ex.Message}");
            }

            return result;
        }

        private static double CalculateEntropy(byte[] data, int offset, int length)
        {
            if (length <= 0) return 0;
            int[] counts = new int[256];
            int end = Math.Min(data.Length, offset + length);
            int actualLength = end - offset;
            if (actualLength <= 0) return 0;

            for (int i = offset; i < end; i++)
            {
                counts[data[i]]++;
            }

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double freq = (double)counts[i] / actualLength;
                    entropy -= freq * Math.Log2(freq);
                }
            }
            return entropy;
        }
    }
}
