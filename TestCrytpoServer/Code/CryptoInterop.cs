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
        var url = new Uri(new Uri(_nav.BaseUri), "js/crypto.js?v=11").ToString();
        return _mod ??= await _js.InvokeAsync<IJSObjectReference>("import", url);
    }

    // --- Pas de passage de mot de passe côté C# ---

    public async Task<object> CreateVaultVerifierFromInputAsync(string inputId, int iterations = 600_000)
        => await (await Mod()).InvokeAsync<object>("createVaultVerifierFromInput", inputId, iterations);

    public async Task<object> OpenVaultFromInputAsync(int vaultId, string inputId, int autoLockMs = 300_000)
        => await (await Mod()).InvokeAsync<object>("openVaultFromInput", vaultId, inputId, autoLockMs);

    public async Task<object> EncryptEntryForOpenVaultAsync()
        => await (await Mod()).InvokeAsync<object>("encryptEntryForOpenVault");

    public async Task RenderVaultEntriesAsync(object records)
        => await (await Mod()).InvokeVoidAsync("renderVaultEntries", records);

    public async Task ClearVaultListAsync()
        => await (await Mod()).InvokeVoidAsync("clearVaultList");

    public async Task LockNowAsync()
        => await (await Mod()).InvokeVoidAsync("lockNow");

    public async Task TouchVaultAsync()
        => await (await Mod()).InvokeVoidAsync("touchVault");
}