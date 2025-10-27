namespace TestCrytpoServer.EF;

public class SecretStore
{
    private readonly AppDbContext _db;

    public SecretStore(AppDbContext db)
    {
        _db = db;
    }

    public async Task AddAsync(SecretRecord record)
    {
        _db.Secrets.Add(record);
        await _db.SaveChangesAsync();
    }

    public async Task<SecretRecord?> FindAsync(int id)
    {
        return await _db.Secrets.FindAsync(id);
    }
}