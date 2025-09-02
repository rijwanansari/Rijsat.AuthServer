using System;

namespace AuthServer.Models;

public class RolePermission
{
    public string RoleId { get; set; } = string.Empty;
    public int PermissionId { get; set; }
    
    public virtual ApplicationRole? Role { get; set; }
    public virtual Permission? Permission { get; set; }
}
