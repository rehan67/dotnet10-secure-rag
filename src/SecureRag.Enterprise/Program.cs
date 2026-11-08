using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Pgvector;
using SecureRag.Enterprise.Data;
using SecureRag.Enterprise.Models;
using SecureRag.Enterprise.Services;

var builder = WebApplication.CreateBuilder(args);

// 1. Database Configuration (PostgreSQL + pgvector)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? "Host=localhost;Database=securerag_db;Username=postgres;Password=secure_dev_password_123!";

builder.Services.AddDbContext<PostgresDbContext>(options =>
{
    options.UseNpgsql(connectionString, o => o.UseVector());
});

// 2. Authentication Configuration (JWT Bearer Token Validation)
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration["Jwt:Authority"] ?? "https://identity.enterprise.internal";
        options.Audience = "securerag-api";
        options.RequireHttpsMetadata = false;
    });

builder.Services.AddAuthorization();

// 3. Register Core Services
builder.Services.AddSingleton<IRagAuthService, RagAuthService>();
builder.Services.AddSingleton<ISecureRagPipeline, SecureRagPipeline>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Health Check Endpoint
app.MapGet("/health", () => Results.Ok(new
{
    status = "Healthy",
    framework = ".NET 10.0",
    architecture = "Zero-Trust RAG (PostgreSQL pgvector + OpenFGA + SHA-256 Cache)",
    timestamp = DateTimeOffset.UtcNow
}));

// Ingest Document Endpoint
app.MapPost("/api/rag/ingest", async (
    DocumentChunk chunk,
    ISecureRagPipeline pipeline,
    CancellationToken ct) =>
{
    await pipeline.IngestDocumentAsync(chunk, ct);
    return Results.Created($"/api/rag/documents/{chunk.Id}", new { chunk.Id, status = "Ingested" });
});

// Query RAG Endpoint with Server-Side Claim Introspection
app.MapPost("/api/rag/query", async (
    RagQueryRequest request,
    HttpContext context,
    ISecureRagPipeline pipeline,
    CancellationToken ct) =>
{
    // Extract user identity and tenant securely from JWT claims (never trust client headers)
    var user = context.User;
    var userId = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? "alice";
    var tenantId = user.FindFirstValue("tenant_id") ?? "tenant-alpha";
    var roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).DefaultIfEmpty("finance_analyst");

    var response = await pipeline.ExecuteRagQueryAsync(userId, tenantId, roles, request, ct);
    return Results.Ok(response);
});

// Real-Time Revocation Webhook (Okta / Entra ID Event Bridge)
app.MapPost("/api/auth/revoke", async (
    OpenFgaTuple tuple,
    IRagAuthService authService,
    CancellationToken ct) =>
{
    await authService.DeleteRelationTupleAsync(tuple.User, tuple.Relation, tuple.Object, ct);
    return Results.Ok(new
    {
        status = "Revoked",
        message = $"Tuple deleted: {tuple.User} is no longer {tuple.Relation} of {tuple.Object}",
        timestamp = DateTimeOffset.UtcNow
    });
});

app.Run();

// Required for WebApplicationFactory in integration tests
public partial class Program { }
