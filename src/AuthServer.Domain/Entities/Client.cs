using System;
using AuthServer.Domain.Common;

namespace AuthServer.Domain.Entities;

public class Client : BaseAuditableEntity
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string ClientSecretHash { get; set; } = string.Empty;
    public bool RequireClientSecret { get; set; } = true;
    public bool IsActive { get; set; } = true;
    
    // Token lifetimes (in seconds)
    public int AccessTokenLifetime { get; set; } = 3600; // 1 hour
    public int RefreshTokenLifetime { get; set; } = 2592000; // 30 days
    public int AuthorizationCodeLifetime { get; set; } = 300; // 5 minutes
    
    // Grant types (comma separated)
    public string AllowedGrantTypes { get; set; } = "authorization_code";
    
    // Redirect URIs (one per line)
    public string RedirectUris { get; set; } = string.Empty;
    public string PostLogoutRedirectUris { get; set; } = string.Empty;
    
    // CORS origins (one per line)
    public string AllowedCorsOrigins { get; set; } = string.Empty;
    
    // PKCE settings
    public bool RequirePkce { get; set; } = true;
    public bool AllowPlainTextPkce { get; set; } = false;
    
    // Consent settings
    public bool RequireConsent { get; set; } = false;
    public bool AllowRememberConsent { get; set; } = true;
    
    // Token settings
    public bool AllowOfflineAccess { get; set; } = false;
    public bool UpdateAccessTokenClaimsOnRefresh { get; set; } = false;
    
    // Navigation properties
    public virtual ICollection<ClientScope> ClientScopes { get; set; } = new List<ClientScope>();
    public virtual ICollection<ClientClaim> ClientClaims { get; set; } = new List<ClientClaim>();
    public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}