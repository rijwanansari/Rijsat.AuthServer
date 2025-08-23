using System;

namespace AuthServer.Domain.Entities;

public class UserLogin
{
    public string LoginProvider { get; set; } = string.Empty;
    public string ProviderKey { get; set; } = string.Empty;
    public string? ProviderDisplayName { get; set; }
    public string UserId { get; set; } = string.Empty;

    public virtual User? User { get; set; }
}
