using System;

namespace AuthServer.Models;

public class ClientScope
{
    public string ClientId { get; set; } = string.Empty;
    public string ScopeName { get; set; } = string.Empty;
    
    public virtual ClientApplication? Client { get; set; }
    public virtual Scope? Scope { get; set; }
}
