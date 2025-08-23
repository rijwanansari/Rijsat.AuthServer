using System;
using AuthServer.Domain.Common;

namespace AuthServer.Domain.Entities;

public class ScopeClaim : BaseEntity
{
    public int Id { get; set; }
    public string ScopeId { get; set; } = string.Empty;
    public string ClaimType { get; set; } = string.Empty;
    
    public virtual Scope? Scope { get; set; }
}
