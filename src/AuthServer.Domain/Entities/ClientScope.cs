using System;

namespace AuthServer.Domain.Entities;

public class ClientScope
{
    public string ClientId { get; set; } = string.Empty;
    public string ScopeId { get; set; } = string.Empty;

    public virtual Client? Client { get; set; }
    public virtual Scope? Scope { get; set; }
}