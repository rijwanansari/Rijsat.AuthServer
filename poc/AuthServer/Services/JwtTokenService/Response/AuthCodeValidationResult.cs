using System;

namespace AuthServer.Services.JwtTokenService.Response;

public class AuthCodeValidationResult
{
    public bool IsValid { get; set; }
    public string UserId { get; set; } = string.Empty;
    public List<string> Scopes { get; set; } = new();
    public string ErrorMessage { get; set; } = string.Empty;
}
