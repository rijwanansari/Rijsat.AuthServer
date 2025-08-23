using System;

namespace AuthServer.Models;

public class RefreshToken
{
    public string Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiryDate { get; set; }
    public bool IsRevoked { get; set; } = false;
    public DateTime CreatedAt { get; set; }
    
    public virtual ApplicationUser? User { get; set; }
}
