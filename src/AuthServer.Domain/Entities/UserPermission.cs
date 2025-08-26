using System;
using AuthServer.Domain.Common;

namespace AuthServer.Domain.Entities;

public class UserPermission : BaseEntity
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public int PermissionId { get; set; }
    public bool IsGranted { get; set; } = true; // Can be used to explicitly deny permissions
    
    public virtual User? User { get; set; }
    public virtual Permission? Permission { get; set; }
}
