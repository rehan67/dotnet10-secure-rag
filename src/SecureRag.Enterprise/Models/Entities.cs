using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Pgvector;

namespace SecureRag.Enterprise.Models;

/// <summary>
/// Physical Tenant-Partitioned Document Chunk Entity
/// </summary>
[Table("document_chunks")]
public class DocumentChunk
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(64)]
    public string TenantId { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string DocumentId { get; set; } = string.Empty;

    [Required]
    [MaxLength(64)]
    public string Department { get; set; } = string.Empty;

    public int ChunkIndex { get; set; }

    [Required]
    public string Content { get; set; } = string.Empty;

    /// <summary>
    /// 1536-Dimensional OpenAI embedding vector
    /// </summary>
    [Column(TypeName = "vector(1536)")]
    public Vector Embedding { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Search Candidate returned from pgvector ANN query before OpenFGA Authorization Sieve
/// </summary>
public record CandidateChunk(
    Guid Id,
    string TenantId,
    string DocumentId,
    string Department,
    string Content,
    double CosineDistance,
    double CosineSimilarity
);

/// <summary>
/// Final Authorized Context Chunk returned after OpenFGA BatchCheck verification
/// </summary>
public record AuthorizedChunk(
    Guid Id,
    string DocumentId,
    string Department,
    string Content,
    double Score,
    bool Authorized
);

/// <summary>
/// Client RAG Query Request Envelope
/// </summary>
public record RagQueryRequest(
    string Prompt,
    int TopK = 5,
    int OverFetchFactor = 4
);

/// <summary>
/// Final Secure RAG Response with Citation Envelopes & Latency Telemetry
/// </summary>
public record RagQueryResponse(
    string Answer,
    IReadOnlyList<AuthorizedChunk> Citations,
    bool CacheHit,
    long LatencyMs,
    int CandidatesFetched,
    int CandidatesAuthorized
);

/// <summary>
/// Relationship Tuples for OpenFGA ReBAC
/// </summary>
public record OpenFgaTuple(
    string User,
    string Relation,
    string Object
);
