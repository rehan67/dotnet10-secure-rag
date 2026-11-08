using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SecureRag.Enterprise.Services;

/// <summary>
/// Cryptographic Security-Aware Semantic Cache Key Generator
/// Enforces physical separation in Redis cache across users with different roles or tenant partitions.
/// </summary>
public static class SecureCacheKeyGenerator
{
    /// <summary>
    /// Computes a deterministic SHA-256 hash combining:
    /// 1. Query Embedding Float Array
    /// 2. Tenant ID
    /// 3. Sorted User Role Assignments
    /// </summary>
    public static string GenerateKey(
        ReadOnlySpan<float> vector,
        string tenantId,
        IEnumerable<string> roles)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentNullException.ThrowIfNull(roles);

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        // 1. Hash the prompt vector bytes
        ReadOnlySpan<byte> vectorBytes = MemoryMarshal.AsBytes(vector);
        sha.AppendData(vectorBytes);

        // 2. Hash the tenant boundary
        sha.AppendData(Encoding.UTF8.GetBytes($"|tenant:{tenantId.Trim().ToLowerInvariant()}|"));

        // 3. Hash sorted canonical roles to avoid permutation bypasses
        var sortedRoles = roles
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => r.Trim().ToLowerInvariant())
            .OrderBy(r => r, StringComparer.Ordinal);

        foreach (var role in sortedRoles)
        {
            sha.AppendData(Encoding.UTF8.GetBytes($"role:{role};"));
        }

        byte[] hash = sha.GetHashAndReset();
        return $"rag:cache:{tenantId}:{Convert.ToHexString(hash).ToLowerInvariant()}";
    }
}
