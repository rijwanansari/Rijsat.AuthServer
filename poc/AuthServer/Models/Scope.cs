using System;

namespace AuthServer.Models;

public class Scope
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    
    public virtual ICollection<ClientScope> ClientScopes { get; set; } = new List<ClientScope>();
}
