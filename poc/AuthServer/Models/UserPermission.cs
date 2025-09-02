using System;

namespace AuthServer.Models;

public class UserPermission
{
    public string UserId { get; set; } = string.Empty;
    public int PermissionId { get; set; }
    public bool IsGranted { get; set; } = true; // Can be used to explicitly deny permissions
    
    public virtual ApplicationUser? User { get; set; }
    public virtual Permission? Permission { get; set; }
}
