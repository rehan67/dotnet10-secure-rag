using Microsoft.EntityFrameworkCore;
using SecureRag.Enterprise.Models;

namespace SecureRag.Enterprise.Data;

public class PostgresDbContext(DbContextOptions<PostgresDbContext> options) : DbContext(options)
{
    public DbSet<DocumentChunk> DocumentChunks => Set<DocumentChunk>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.HasPostgresExtension("vector");

        modelBuilder.Entity<DocumentChunk>(entity =>
        {
            entity.HasKey(e => new { e.TenantId, e.Id });
            entity.Property(e => e.Embedding).HasColumnType("vector(1536)");

            entity.HasIndex(e => new { e.TenantId, e.Department });
            entity.HasIndex(e => new { e.TenantId, e.DocumentId });
        });
    }
}
