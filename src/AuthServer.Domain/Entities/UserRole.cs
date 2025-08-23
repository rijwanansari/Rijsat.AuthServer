using System;

namespace AuthServer.Domain.Entities;

public class UserRole
{
    public string UserId { get; set; } = string.Empty;
    public string RoleId { get; set; } = string.Empty;

    public virtual User? User { get; set; }
    public virtual Role? Role { get; set; }
}
