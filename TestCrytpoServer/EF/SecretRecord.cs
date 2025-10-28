namespace TestCrytpoServer.EF;

public class SecretRecord
{
    public int Id { get; set; }

    public string CipherPasswordB64 { get; set; } = "";
    public string IvPasswordB64 { get; set; } = "";

    public string CipherNameB64 { get; set; } = "";
    public string IvNameB64 { get; set; } = "";

    public string CipherUrlB64 { get; set; } = "";
    public string IvUrlB64 { get; set; } = "";

    public string CipherNotesB64 { get; set; } = "";
    public string IvNotesB64 { get; set; } = "";

    public string SaltB64 { get; set; } = "";
    public int Iterations { get; set; }
}