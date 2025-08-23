using System;
using AuthServer.Domain.Common;

namespace AuthServer.Domain.Entities;

public class UserClaim : BaseEntity
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string? ClaimType { get; set; }
    public string? ClaimValue { get; set; }

    public virtual User? User { get; set; }
}