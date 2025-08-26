using AuthServer.Domain.Common;
using System;

namespace AuthServer.Domain.Entities;

public class UserToken :BaseEntity
{
    public long Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string LoginProvider { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Value { get; set; }

    public virtual User? User { get; set; }
}
