using System;
using AuthServer.Domain.Common;

namespace AuthServer.Domain.Entities;

public class RefreshToken : BaseAuditableEntity
{
    public string Token { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty; // Space-separated scopes
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; } = false;
    public DateTime? RevokedAt { get; set; }
    public string? RevokedBy { get; set; }
    public string? ReplacedByToken { get; set; }
    
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public bool IsActive => !IsRevoked && !IsExpired;
    
    // Navigation properties
    public virtual User? User { get; set; }
    public virtual Client? Client { get; set; }
}
