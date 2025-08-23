using System;

namespace AuthServer.Models;

public class AuthorizationCode
{
    public string Code { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public DateTime ExpiryDate { get; set; }
    public bool IsUsed { get; set; } = false;
    public DateTime CreatedAt { get; set; }
    
    // PKCE support
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
}
