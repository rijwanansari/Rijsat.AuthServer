using System;

namespace AuthServer.Application.Common.Models;

public class RegisterClientRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string ClientSecret { get; set; } = string.Empty;
    public string? AllowedGrantTypes { get; set; }
    public string? RedirectUris { get; set; }
    public string? PostLogoutRedirectUris { get; set; }
    public string? AllowedCorsOrigins { get; set; }
    public bool RequirePkce { get; set; } = true;
    public bool AllowPlainTextPkce { get; set; } = false;
    public bool RequireConsent { get; set; } = false;
    public bool AllowRememberConsent { get; set; } = true;
    public bool AllowOfflineAccess { get; set; } = false;
    public int? AccessTokenLifetime { get; set; }
    public int? RefreshTokenLifetime { get; set; }
    public int? AuthorizationCodeLifetime { get; set; }
}
