using AuthServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Application.Common.Interfaces;

public interface IApplicationDbContext
{
    DbSet<User> Users { get; set; }
    DbSet<Role> Roles { get; set; }
    DbSet<UserRole> UserRoles { get; set; }
    DbSet<UserClaim> UserClaims { get; set; }
    DbSet<RoleClaim> RoleClaims { get; set; }
    DbSet<UserLogin> UserLogins { get; set; }
    DbSet<UserToken> UserTokens { get; set; }
    DbSet<Client> Clients { get; set; }
    DbSet<Scope> Scopes { get; set; }
    DbSet<ClientScope> ClientScopes { get; set; }
    DbSet<ScopeClaim> ScopeClaims { get; set; }
    DbSet<ClientClaim> ClientClaims { get; set; }
    DbSet<Permission> Permissions { get; set; }
    DbSet<RolePermission> RolePermissions { get; set; }
    DbSet<UserPermission> UserPermissions { get; set; }
    DbSet<RefreshToken> RefreshTokens { get; set; }
    DbSet<AuthorizationCode> AuthorizationCodes { get; set; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
