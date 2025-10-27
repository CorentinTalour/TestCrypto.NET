namespace TestCrytpoServer.EF;

public class SecretRecord
{
    public int Id { get; set; }
    public string CiphertextB64 { get; set; } = "";
    public string IvB64 { get; set; } = "";
    public string SaltB64 { get; set; } = "";
    public int Iterations { get; set; }
}