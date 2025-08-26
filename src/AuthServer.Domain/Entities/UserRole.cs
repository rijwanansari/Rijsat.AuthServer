using AuthServer.Domain.Common;
using System;

namespace AuthServer.Domain.Entities;

public class UserRole : BaseEntity
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string RoleId { get; set; } = string.Empty;

    public virtual User? User { get; set; }
    public virtual Role? Role { get; set; }
}
