using System;
using AuthServer.Domain.Common;

namespace AuthServer.Domain.Entities;

public class ClientClaim : BaseEntity
{
    public int Id { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string ClaimType { get; set; } = string.Empty;
    public string ClaimValue { get; set; } = string.Empty;
    
    public virtual Client? Client { get; set; }
}
