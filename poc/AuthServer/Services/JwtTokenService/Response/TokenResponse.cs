using System;

namespace AuthServer.Services.JwtTokenService.Response;

public class TokenResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = "Bearer";
    public int ExpiresIn { get; set; }
    public List<string> Scopes { get; set; } = new();
}
