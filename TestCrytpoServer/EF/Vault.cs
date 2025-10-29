namespace TestCrytpoServer.EF;

public class Vault
{
    public int Id { get; set; }
    public string OwnerUserId { get; set; } = ""; // ou GUID selon ton modèle utilisateur
    public string VaultSaltB64 { get; set; } = "";
    public int Iterations { get; set; }
    public string VerifierB64 { get; set; } = ""; // valeur stockée pour vérifier le MP
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    
    public List<SecretRecord> Secrets { get; set; } = new();
}