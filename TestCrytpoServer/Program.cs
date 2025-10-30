using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using TestCrytpoServer.Code;
using TestCrytpoServer.Components;
using TestCrytpoServer.EF;

var builder = WebApplication.CreateBuilder(args);

// --- SERVICES ---
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<CryptoInterop>();
builder.Services.AddHttpClient();

var app = builder.Build();

// --- MIDDLEWARES ---
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

// --- ROUTES BLAZOR ---
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();


// ----------------------------------------------------------------------
// Helpers PBKDF2 / Base64
// ----------------------------------------------------------------------
static byte[] DerivePbkdf2Sha256(string password, byte[] salt, int iterations, int dkLenBytes = 32)
{
    var pwdBytes = Encoding.UTF8.GetBytes(password ?? string.Empty);
    var dk = new byte[dkLenBytes];
    Rfc2898DeriveBytes.Pbkdf2(
        password: pwdBytes,
        salt: salt,
        iterations: iterations,
        hashAlgorithm: HashAlgorithmName.SHA256,
        destination: dk
    );
    Array.Clear(pwdBytes, 0, pwdBytes.Length);
    return dk;
}

static string B64(byte[] b) => Convert.ToBase64String(b);
static byte[] B64d(string s) => Convert.FromBase64String(s);

// ----------------------------------------------------------------------
// --- API VAULT (mode unique utilisé par l’app)
// ----------------------------------------------------------------------

// Création d’un vault : reçoit le MP en clair, génère sel+hash et stocke
app.MapPost("/api/vaults", async (AppDbContext db, JsonElement input) =>
{
    // Input attendu : { ownerUserId?: string, password: string, iterations?: number }
    if (!input.TryGetProperty("password", out var pwdProp))
        return Results.BadRequest("Missing 'password'");

    string password = pwdProp.GetString() ?? string.Empty;
    string ownerUserId = input.TryGetProperty("ownerUserId", out var ownerProp) ? (ownerProp.GetString() ?? "") : "";
    int iterations = input.TryGetProperty("iterations", out var iterProp) ? iterProp.GetInt32() : 600_000;
    if (iterations <= 0) iterations = 600_000;

    // Génère sel 16o et dérive 32o (PBKDF2-HMAC-SHA256)
    var salt = RandomNumberGenerator.GetBytes(16);
    var dk = DerivePbkdf2Sha256(password, salt, iterations); // 32 octets

    var v = new Vault
    {
        OwnerUserId  = ownerUserId,
        VaultSaltB64 = B64(salt),
        Iterations   = iterations,
        // On réutilise la colonne VerifierB64 pour stocker le dérivé PBKDF2
        VerifierB64  = B64(dk),
        CreatedAt    = DateTimeOffset.UtcNow
    };

    db.Vaults.Add(v);
    await db.SaveChangesAsync();

    // IMPORTANT : renvoyer 'vaultId' pour matcher le front
    return Results.Created($"/api/vaults/{v.Id}", new {
        vaultId = v.Id,
        vaultSaltB64 = v.VaultSaltB64,
        iterations = v.Iterations
    });
}).DisableAntiforgery();

// Lecture des paramètres (pour dérivation côté client)
app.MapGet("/api/vaults/{vaultId:int}/params", async (AppDbContext db, int vaultId) =>
{
    var v = await db.Vaults.FindAsync(vaultId);
    return v is null
        ? Results.NotFound()
        : Results.Ok(new { v.VaultSaltB64, v.Iterations });
}).DisableAntiforgery();

// Vérification MP : reçoit le MP en clair, re-dérive et compare (temps constant)
app.MapPost("/api/vaults/{vaultId:int}/check", async (AppDbContext db, int vaultId, JsonElement input) =>
{
    var v = await db.Vaults.FindAsync(vaultId);
    if (v is null) return Results.NotFound();

    if (!input.TryGetProperty("password", out var pwdProp))
        return Results.BadRequest("Missing 'password'");

    string password = pwdProp.GetString() ?? string.Empty;

    var salt = B64d(v.VaultSaltB64);
    var expected = B64d(v.VerifierB64);
    var dk = DerivePbkdf2Sha256(password, salt, v.Iterations);

    bool ok = CryptographicOperations.FixedTimeEquals(dk, expected);
    Array.Clear(dk, 0, dk.Length);

    return Results.Ok(new { ok });
}).DisableAntiforgery();

// Créer une entrée chiffrée dans un vault (AES-GCM via clé du vault, côté client)
app.MapPost("/api/vaults/{vaultId:int}/entries", async (AppDbContext db, int vaultId, VaultEntryIn input) =>
{
    var rec = new SecretRecord
    {
        VaultId = vaultId,

        CipherPasswordB64 = input.cipherPasswordB64,
        TagPasswordB64    = input.tagPasswordB64,
        IvPasswordB64     = input.ivPasswordB64,

        CipherNameB64 = input.cipherNameB64,
        TagNameB64    = input.tagNameB64,
        IvNameB64     = input.ivNameB64,

        CipherUrlB64 = input.cipherUrlB64,
        TagUrlB64    = input.tagUrlB64,
        IvUrlB64     = input.ivUrlB64,

        CipherNotesB64 = input.cipherNotesB64,
        TagNotesB64    = input.tagNotesB64,
        IvNotesB64     = input.ivNotesB64
    };

    db.Secrets.Add(rec);
    await db.SaveChangesAsync();
    return Results.Created($"/api/vaults/{vaultId}/entries/{rec.Id}", new { id = rec.Id });
}).DisableAntiforgery();

// Lister les entrées d’un vault (toujours chiffrées)
app.MapGet("/api/vaults/{vaultId:int}/entries", async (AppDbContext db, int vaultId) =>
{
    var list = await db.Secrets.Where(s => s.VaultId == vaultId)
        .Select(s => new {
            id = s.Id,

            s.CipherPasswordB64, s.TagPasswordB64, s.IvPasswordB64,
            s.CipherNameB64,     s.TagNameB64,     s.IvNameB64,
            s.CipherUrlB64,      s.TagUrlB64,      s.IvUrlB64,
            s.CipherNotesB64,    s.TagNotesB64,    s.IvNotesB64
        })
        .ToListAsync();

    return Results.Ok(list);
}).DisableAntiforgery();

app.Run();

// --- DTO pour POST /entries uniquement ---
public record VaultEntryIn(
    string cipherPasswordB64, string tagPasswordB64, string ivPasswordB64,
    string cipherNameB64,     string tagNameB64,     string ivNameB64,
    string cipherUrlB64,      string tagUrlB64,      string ivUrlB64,
    string cipherNotesB64,    string tagNotesB64,    string ivNotesB64);