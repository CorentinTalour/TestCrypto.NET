using Microsoft.EntityFrameworkCore;
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
builder.Services.AddScoped<SecretStore>();
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
// --- API "blind storage" pour secrets (inchangée)
// ----------------------------------------------------------------------
// app.MapPost("/api/secrets", async (SecretStore store, SecretRecordIn input) =>
// {
//     var rec = new SecretRecord
//     {
//         CipherPasswordB64 = input.cipherPasswordB64, TagPasswordB64 = input.tagPasswordB64,
//         IvPasswordB64 = input.ivPasswordB64,
//         CipherNameB64 = input.cipherNameB64, TagNameB64 = input.tagNameB64, IvNameB64 = input.ivNameB64,
//         CipherUrlB64 = input.cipherUrlB64, TagUrlB64 = input.tagUrlB64, IvUrlB64 = input.ivUrlB64,
//         CipherNotesB64 = input.cipherNotesB64, TagNotesB64 = input.tagNotesB64, IvNotesB64 = input.ivNotesB64,
//         SaltB64 = input.saltB64, Iterations = input.iterations
//     };
//     await store.AddAsync(rec);
//     return Results.Ok(new { id = rec.Id });
// }).DisableAntiforgery();

// app.MapPost("/api/secrets", async (HttpRequest req) =>
// {
//     using var reader = new StreamReader(req.Body);
//     var body = await reader.ReadToEndAsync();
//     Console.WriteLine("[/api/secrets] BODY RAW: " + body);
//     return Results.BadRequest("DEBUG BODY PRINTED"); // évite d'insérer en base
// });

app.MapGet("/api/secrets/{id:int}", async (SecretStore store, int id) =>
{
    var r = await store.FindAsync(id);
    return r is null ? Results.NotFound() :
        Results.Ok(new {
            r.Id,
            r.CipherPasswordB64, r.TagPasswordB64, r.IvPasswordB64,
            r.CipherNameB64,     r.TagNameB64,     r.IvNameB64,
            r.CipherUrlB64,      r.TagUrlB64,      r.IvUrlB64,
            r.CipherNotesB64,    r.TagNotesB64,    r.IvNotesB64,
        });
}).DisableAntiforgery();


// ----------------------------------------------------------------------
// --- API VAULT (simplifiée, sans DTO)
// ----------------------------------------------------------------------

// Création d’un vault
app.MapPost("/api/vaults", async (AppDbContext db, JsonElement input) =>
{
    if (!input.TryGetProperty("ownerUserId", out var ownerProp) ||
        !input.TryGetProperty("vaultSaltB64", out var saltProp) ||
        !input.TryGetProperty("iterations", out var iterProp) ||
        !input.TryGetProperty("verifierB64", out var verProp))
    {
        return Results.BadRequest("Invalid payload");
    }

    var v = new Vault
    {
        OwnerUserId = ownerProp.GetString() ?? "",
        VaultSaltB64 = saltProp.GetString() ?? "",
        Iterations = iterProp.GetInt32(),
        VerifierB64 = verProp.GetString() ?? "",
        CreatedAt = DateTimeOffset.UtcNow
    };

    db.Vaults.Add(v);
    await db.SaveChangesAsync();
    return Results.Created($"/api/vaults/{v.Id}", new { id = v.Id });
}).DisableAntiforgery();


// Lecture des paramètres (pour dérivation)
app.MapGet("/api/vaults/{id:int}/params", async (AppDbContext db, int id) =>
{
    var v = await db.Vaults.FindAsync(id);
    return v is null
        ? Results.NotFound()
        : Results.Ok(new { v.VaultSaltB64, v.Iterations });
}).DisableAntiforgery();


// Vérification d’un mot de passe maître
app.MapPost("/api/vaults/{vaultId:int}/check", async (AppDbContext db, int vaultId, JsonElement input) =>
{
    var v = await db.Vaults.FindAsync(vaultId);
    if (v is null) return Results.NotFound();

    if (!input.TryGetProperty("verifierB64", out var verProp))
        return Results.BadRequest("Invalid payload");

    bool ok = string.Equals(verProp.GetString(), v.VerifierB64, StringComparison.Ordinal);
    return Results.Ok(new { ok });
}).DisableAntiforgery();

// Créer une entrée dans un vault
app.MapPost("/api/vaults/{vaultId:int}/entries", async (AppDbContext db, int vaultId, VaultEntryIn input) =>
{
    var rec = new SecretRecord
    {
        VaultId = vaultId,
        CipherPasswordB64 = input.cipherPasswordB64, TagPasswordB64 = input.tagPasswordB64, IvPasswordB64 = input.ivPasswordB64,
        CipherNameB64     = input.cipherNameB64,     TagNameB64     = input.tagNameB64,     IvNameB64     = input.ivNameB64,
        CipherUrlB64      = input.cipherUrlB64,      TagUrlB64      = input.tagUrlB64,      IvUrlB64      = input.ivUrlB64,
        CipherNotesB64    = input.cipherNotesB64,    TagNotesB64    = input.tagNotesB64,    IvNotesB64    = input.ivNotesB64,
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

// --- RECORDS POUR SECRETS UNIQUEMENT ---
public record SecretRecordIn(
    string cipherPasswordB64, string tagPasswordB64, string ivPasswordB64,
    string cipherNameB64,     string tagNameB64,     string ivNameB64,
    string cipherUrlB64,      string tagUrlB64,      string ivUrlB64,
    string cipherNotesB64,    string tagNotesB64,    string ivNotesB64,
    string saltB64, int iterations);
    
public record VaultEntryIn(
    string cipherPasswordB64, string tagPasswordB64, string ivPasswordB64,
    string cipherNameB64,     string tagNameB64,     string ivNameB64,
    string cipherUrlB64,      string tagUrlB64,      string ivUrlB64,
    string cipherNotesB64,    string tagNotesB64,    string ivNotesB64);