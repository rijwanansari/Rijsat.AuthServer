using System;

namespace AuthServer.Models;

public class ClientApplication
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty; // Hashed
    public string Description { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    // Allowed grant types (comma separated)
    public string AllowedGrantTypes { get; set; } = "authorization_code";
    
    // Allowed redirect URIs (comma separated)
    public string RedirectUris { get; set; } = string.Empty;
    
    // Allowed scopes (comma separated)
    public string AllowedScopes { get; set; } = string.Empty;
    
    // Token lifetime in seconds
    public int AccessTokenLifetime { get; set; } = 3600; // 1 hour
    public int RefreshTokenLifetime { get; set; } = 2592000; // 30 days
    
    public virtual ICollection<ClientScope> ClientScopes { get; set; } = new List<ClientScope>();
}
