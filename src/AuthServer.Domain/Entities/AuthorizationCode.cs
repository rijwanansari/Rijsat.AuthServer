using System;
using AuthServer.Domain.Common;

namespace AuthServer.Domain.Entities;

public class AuthorizationCode : BaseEntity
{
    public string Code { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty; // Space-separated scopes
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; } = false;
    public DateTime? UsedAt { get; set; }
    
    // PKCE support
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    
    // Additional OAuth2 parameters
    public string? State { get; set; }
    public string? Nonce { get; set; }
    
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public bool IsActive => !IsUsed && !IsExpired;
    
    // Navigation properties
    public virtual User? User { get; set; }
    public virtual Client? Client { get; set; }
}
