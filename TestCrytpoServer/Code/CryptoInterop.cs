using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace TestCrytpoServer.Code;

public class CryptoInterop
{
    private readonly IJSRuntime _js;
    private readonly NavigationManager _nav;
    private IJSObjectReference? _mod;

    public CryptoInterop(IJSRuntime js, NavigationManager nav)
    {
        _js = js;
        _nav = nav;
    }

    private async Task<IJSObjectReference> Mod()
    {
        // bump version si tu touches crypto.js
        var url = new Uri(new Uri(_nav.BaseUri), "js/crypto.js?v=10").ToString();
        return _mod ??= await _js.InvokeAsync<IJSObjectReference>("import", url);
    }

    // --- SAFE: le MP reste dans le navigateur ---

    // Crée salt/verifier/iterations à partir de #input côté client (MP pas renvoyé)
    public async Task<object> CreateVaultVerifierFromInputAsync(string inputId, int iterations = 600_000)
        => await (await Mod()).InvokeAsync<object>("createVaultVerifierFromInput", inputId, iterations);

    // Ouvre le vault en lisant le MP depuis #input côté client (MP pas renvoyé)
    public async Task<object> OpenVaultFromInputAsync(int vaultId, string inputId)
        => await (await Mod()).InvokeAsync<object>("openVaultFromInput", vaultId, inputId);

    // Chiffre une nouvelle entrée avec la clé du vault en RAM (client)
    public async Task<object> EncryptEntryForOpenVaultAsync()
        => await (await Mod()).InvokeAsync<object>("encryptEntryForOpenVault");

    // Déchiffre une entrée (client) et affiche dans le DOM
    public async Task RenderVaultEntriesAsync(object records)
        => await (await Mod()).InvokeVoidAsync("renderVaultEntries", records);

    public async Task ClearVaultListAsync()
        => await (await Mod()).InvokeVoidAsync("clearVaultList");
    
    public async Task<object> CreateVaultVerifierAsync(string password, int iterations = 600_000)
        => await (await Mod()).InvokeAsync<object>("createVaultVerifier", password, iterations);

    public async Task<object> OpenVaultAsync(int vaultId, string password)
        => await (await Mod()).InvokeAsync<object>("openVault", vaultId, password);
}