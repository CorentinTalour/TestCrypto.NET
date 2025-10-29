namespace TestCrytpoServer.EF;

public class SecretRecord
{
    public int Id { get; set; }
    public int VaultId { get; set; }

    public Vault? Vault { get; set; }

    public string CipherPasswordB64 { get; set; } = "";
    public string TagPasswordB64 { get; set; } = "";
    public string IvPasswordB64 { get; set; } = "";

    public string CipherNameB64 { get; set; } = "";
    public string TagNameB64 { get; set; } = "";
    public string IvNameB64 { get; set; } = "";

    public string CipherUrlB64 { get; set; } = "";
    public string TagUrlB64 { get; set; } = "";
    public string IvUrlB64 { get; set; } = "";

    public string CipherNotesB64 { get; set; } = "";
    public string TagNotesB64 { get; set; } = "";
    public string IvNotesB64 { get; set; } = "";
}