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
        var url = new Uri(new Uri(_nav.BaseUri), "js/crypto.js").ToString();
        return _mod ??= await _js.InvokeAsync<IJSObjectReference>("import", url);
    }

    public record EncryptResult(string ciphertextB64, string ivB64, string saltB64, int iterations);
    public async Task<EncryptResult> EncryptAsync(string plaintext, string password, int iterations = 600_000)
        => await (await Mod()).InvokeAsync<EncryptResult>("encryptPBKDF2_GCM", plaintext, password, iterations);
    public async Task<string> DecryptAsync(string ciphertextB64, string password, string ivB64, string saltB64, int iterations)
        => await (await Mod()).InvokeAsync<string>("decryptPBKDF2_GCM", ciphertextB64, password, ivB64, saltB64, iterations);
}