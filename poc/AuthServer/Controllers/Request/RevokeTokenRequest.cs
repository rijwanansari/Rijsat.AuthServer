using System;

namespace AuthServer.Controllers.Request;

public class RevokeTokenRequest
{
    public required string Token { get; set; } = string.Empty;
    
    public string? TokenTypeHint { get; set; }
}
