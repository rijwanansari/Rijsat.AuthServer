using System;
using AuthServer.Domain.Common;

namespace AuthServer.Domain.Entities;

public class RoleClaim : BaseEntity
{
    public int Id { get; set; }
    public string RoleId { get; set; } = string.Empty;
    public string? ClaimType { get; set; }
    public string? ClaimValue { get; set; }

    public virtual Role? Role { get; set; }
}
