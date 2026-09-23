using System.IO;
using System.Security.Cryptography;

namespace xScanner.Analysis
{
    public class Heuristics
    {
        public static string ComputeSha256(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            byte[] hash = sha256.ComputeHash(stream);
            return System.BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        public static bool EvaluateSuspicious(PEAnalysisResult peResult)
        {
            return peResult.IsSuspicious || peResult.MaxEntropy > 7.3;
        }
    }
}
