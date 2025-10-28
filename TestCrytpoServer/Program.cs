using Microsoft.EntityFrameworkCore;
using TestCrytpoServer.Code;
using TestCrytpoServer.Components;
using TestCrytpoServer.EF;

var builder = WebApplication.CreateBuilder(args);

// --- SERVICES ---
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// EF Core (connexion à ton SQL Server Docker)
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Tes services custom
builder.Services.AddScoped<CryptoInterop>();
builder.Services.AddScoped<SecretStore>();
builder.Services.AddHttpClient();

// --- BUILD PIPELINE ---
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

// --- API "blind storage" ---
app.MapPost("/api/secrets", async (SecretStore store, SecretRecordIn input) =>
{
    var rec = new SecretRecord {
        CipherPasswordB64 = input.cipherPasswordB64, IvPasswordB64 = input.ivPasswordB64,
        CipherNameB64     = input.cipherNameB64,     IvNameB64     = input.ivNameB64,
        CipherUrlB64      = input.cipherUrlB64,      IvUrlB64      = input.ivUrlB64,
        CipherNotesB64    = input.cipherNotesB64,    IvNotesB64    = input.ivNotesB64,
        SaltB64           = input.saltB64,           Iterations    = input.iterations
    };
    await store.AddAsync(rec);
    return Results.Ok(new { id = rec.Id });
}).DisableAntiforgery();

app.MapGet("/api/secrets/{id:int}", async (SecretStore store, int id) =>
{
    var r = await store.FindAsync(id);
    return r is null ? Results.NotFound() :
        Results.Ok(new {
            r.Id,
            r.CipherPasswordB64, r.IvPasswordB64,
            r.CipherNameB64,     r.IvNameB64,
            r.CipherUrlB64,      r.IvUrlB64,
            r.CipherNotesB64,    r.IvNotesB64,
            r.SaltB64,           r.Iterations
        });
}).DisableAntiforgery();

app.Run();

// --- RECORDS ---
public record SecretRecordIn(
    string cipherPasswordB64, string ivPasswordB64,
    string cipherNameB64,     string ivNameB64,
    string cipherUrlB64,      string ivUrlB64,
    string cipherNotesB64,    string ivNotesB64,
    string saltB64, int iterations);
