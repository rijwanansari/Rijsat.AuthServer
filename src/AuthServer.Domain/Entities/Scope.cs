using System;
using AuthServer.Domain.Common;
using AuthServer.Domain.Enums;

namespace AuthServer.Domain.Entities;

public class Scope : BaseAuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool Required { get; set; } = false;
    public bool Emphasize { get; set; } = false;
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public bool IsActive { get; set; } = true;
    public ScopeType Type { get; set; } = ScopeType.Resource;
    
    // Navigation properties
    public virtual ICollection<ClientScope> ClientScopes { get; set; } = new List<ClientScope>();
    public virtual ICollection<ScopeClaim> ScopeClaims { get; set; } = new List<ScopeClaim>();
}
