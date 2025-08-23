using System;

namespace AuthServer.Domain.Entities;

public class RolePermission
{
    public string RoleId { get; set; } = string.Empty;
    public int PermissionId { get; set; }
    
    public virtual Role? Role { get; set; }
    public virtual Permission? Permission { get; set; }
}
