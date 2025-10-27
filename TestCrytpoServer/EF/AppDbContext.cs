using Microsoft.EntityFrameworkCore;

namespace TestCrytpoServer.EF;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<SecretRecord> Secrets => Set<SecretRecord>();
}