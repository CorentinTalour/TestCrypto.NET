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
app.MapPost("/api/secrets", async (SecretStore store, SecretRecordIn input, ILoggerFactory lf) =>
{
    var log = lf.CreateLogger("Secrets");
    try
    {
        var rec = new SecretRecord
        {
            CiphertextB64 = input.ciphertextB64,
            IvB64 = input.ivB64,
            SaltB64 = input.saltB64,
            Iterations = input.iterations
        };
        await store.AddAsync(rec);
        return Results.Ok(new { id = rec.Id });
    }
    catch (Exception ex)
    {
        log.LogError(ex, "Insert failed");
        return Results.Problem(ex.Message, statusCode: 500);
    }
}).DisableAntiforgery();

app.MapGet("/api/secrets/{id:int}", async (SecretStore store, int id) =>
{
    var rec = await store.FindAsync(id);
    return rec is null ? Results.NotFound()
        : Results.Ok(new { rec.Id, rec.CiphertextB64, rec.IvB64, rec.SaltB64, rec.Iterations });
}).DisableAntiforgery(); 

app.Run();

// --- RECORDS ---
public record SecretRecordIn(string ciphertextB64, string ivB64, string saltB64, int iterations);