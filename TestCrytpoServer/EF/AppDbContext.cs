using Microsoft.EntityFrameworkCore;

namespace TestCrytpoServer.EF;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<SecretRecord> Secrets => Set<SecretRecord>();
    public DbSet<Vault> Vaults => Set<Vault>();
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<SecretRecord>()
            .HasOne(s => s.Vault)
            .WithMany(v => v.Secrets)
            .HasForeignKey(s => s.VaultId)
            .OnDelete(DeleteBehavior.Cascade); // supprime les entrées si le vault est supprimé
    }
}