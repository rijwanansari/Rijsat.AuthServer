using AuthServer.Domain.Entities;
using AuthServer.Domain.Enums;
using AuthServer.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthServer.Infrastructure.Data;

public static class ApplicationDbContextSeed
{
    public static async Task SeedDefaultDataAsync(ApplicationDbContext context, ILogger logger)
    {
        try
        {
            await SeedRolesAsync(context);
            await SeedPermissionsAsync(context);
            await SeedScopesAsync(context);
            await SeedClientsAsync(context);
            await SeedRolePermissionsAsync(context);
            await SeedDefaultUserAsync(context);

            await context.SaveChangesAsync();
            logger.LogInformation("Database seeded successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while seeding the database");
        }
    }

    private static async Task SeedRolesAsync(ApplicationDbContext context)
    {
        if (!await context.Roles.AnyAsync())
        {
            var roles = new[]
            {
                new Role { Id = "1", Name = "Admin", NormalizedName = "ADMIN", Description = "System Administrator" },
                new Role { Id = "2", Name = "User", NormalizedName = "USER", Description = "Standard User" },
                new Role { Id = "3", Name = "Manager", NormalizedName = "MANAGER", Description = "Manager Role" }
            };

            context.Roles.AddRange(roles);
        }
    }

    private static async Task SeedPermissionsAsync(ApplicationDbContext context)
    {
        if (!await context.Permissions.AnyAsync())
        {
            var permissions = new[]
            {
                new Permission { Id = 1, Name = "users.read", DisplayName = "Read Users", Description = "Read users", Category = "Users" },
                new Permission { Id = 2, Name = "users.write", DisplayName = "Write Users", Description = "Write users", Category = "Users" },
                new Permission { Id = 3, Name = "users.delete", DisplayName = "Delete Users", Description = "Delete users", Category = "Users" },
                new Permission { Id = 4, Name = "roles.read", DisplayName = "Read Roles", Description = "Read roles", Category = "Roles" },
                new Permission { Id = 5, Name = "roles.write", DisplayName = "Write Roles", Description = "Write roles", Category = "Roles" },
                new Permission { Id = 6, Name = "api.read", DisplayName = "Read API", Description = "Read API access", Category = "API" },
                new Permission { Id = 7, Name = "api.write", DisplayName = "Write API", Description = "Write API access", Category = "API" }
            };

            context.Permissions.AddRange(permissions);
        }
    }

    private static async Task SeedScopesAsync(ApplicationDbContext context)
    {
        if (!await context.Scopes.AnyAsync())
        {
            var scopes = new[]
            {
                new Scope { Id = "1", Name = "openid", DisplayName = "OpenID", Description = "OpenID Connect", Type = ScopeType.Identity },
                new Scope { Id = "2", Name = "profile", DisplayName = "Profile", Description = "User profile information", Type = ScopeType.Identity },
                new Scope { Id = "3", Name = "email", DisplayName = "Email", Description = "User email address", Type = ScopeType.Identity },
                new Scope { Id = "4", Name = "api", DisplayName = "API Access", Description = "Access to protected APIs", Type = ScopeType.Resource },
                new Scope { Id = "5", Name = "offline_access", DisplayName = "Offline Access", Description = "Refresh token access", Type = ScopeType.Resource }
            };

            context.Scopes.AddRange(scopes);
        }
    }

    private static async Task SeedClientsAsync(ApplicationDbContext context)
    {
        if (!await context.Clients.AnyAsync())
        {
            var passwordHasher = new PasswordHasher();

            var clients = new[]
            {
                new Client
                {
                    Id = "1",
                    ClientId = "web-app",
                    ClientName = "Web Application",
                    ClientSecretHash = passwordHasher.HashPassword("web-app-secret"),
                    Description = "Main web application client",
                    AllowedGrantTypes = "authorization_code,refresh_token",
                    RedirectUris = "https://localhost:5002/signin-callback\nhttps://localhost:5002/callback",
                    PostLogoutRedirectUris = "https://localhost:5002/signout-callback",
                    AllowedCorsOrigins = "https://localhost:5002",
                    RequirePkce = true,
                    AllowOfflineAccess = true,
                    AccessTokenLifetime = 3600,
                    RefreshTokenLifetime = 2592000
                },
                new Client
                {
                    Id = "2",
                    ClientId = "spa-app",
                    ClientName = "SPA Application",
                    RequireClientSecret = false,
                    Description = "Single Page Application",
                    AllowedGrantTypes = "authorization_code",
                    RedirectUris = "http://localhost:3000/callback\nhttp://localhost:3000/silent-callback",
                    PostLogoutRedirectUris = "http://localhost:3000/",
                    AllowedCorsOrigins = "http://localhost:3000",
                    RequirePkce = true,
                    RequireConsent = false,
                    AccessTokenLifetime = 3600
                },
                new Client
                {
                    Id = "3",
                    ClientId = "api-client",
                    ClientName = "API Client",
                    ClientSecretHash = passwordHasher.HashPassword("api-client-secret"),
                    Description = "Server-to-server API client",
                    AllowedGrantTypes = "client_credentials",
                    RequirePkce = false,
                    AccessTokenLifetime = 3600
                }
            };

            context.Clients.AddRange(clients);
        }
    }

    private static async Task SeedRolePermissionsAsync(ApplicationDbContext context)
    {
        if (!await context.RolePermissions.AnyAsync())
        {
            var rolePermissions = new List<RolePermission>();

            // Admin gets all permissions
            for (int i = 1; i <= 7; i++)
            {
                rolePermissions.Add(new RolePermission { RoleId = "1", PermissionId = i });
            }

            // User gets basic API permissions
            rolePermissions.Add(new RolePermission { RoleId = "2", PermissionId = 6 }); // api.read
            rolePermissions.Add(new RolePermission { RoleId = "2", PermissionId = 7 }); // api.write

            // Manager gets user management permissions
            rolePermissions.Add(new RolePermission { RoleId = "3", PermissionId = 1 }); // users.read
            rolePermissions.Add(new RolePermission { RoleId = "3", PermissionId = 2 }); // users.write
            rolePermissions.Add(new RolePermission { RoleId = "3", PermissionId = 4 }); // roles.read
            rolePermissions.Add(new RolePermission { RoleId = "3", PermissionId = 6 }); // api.read
            rolePermissions.Add(new RolePermission { RoleId = "3", PermissionId = 7 }); // api.write

            context.RolePermissions.AddRange(rolePermissions);
        }
    }

    private static async Task SeedDefaultUserAsync(ApplicationDbContext context)
    {
        if (!await context.Users.AnyAsync())
        {
            var passwordHasher = new PasswordHasher();

            var adminUser = new User
            {
                Id = "1",
                UserName = "admin@authserver.com",
                Email = "admin@authserver.com",
                FirstName = "System",
                LastName = "Administrator",
                PasswordHash = passwordHasher.HashPassword("Admin123!"),
                EmailConfirmed = true,
                IsActive = true,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var testUser = new User
            {
                Id = "2",
                UserName = "user@test.com",
                Email = "user@test.com",
                FirstName = "Test",
                LastName = "User",
                PasswordHash = passwordHasher.HashPassword("User123!"),
                EmailConfirmed = true,
                IsActive = true,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            context.Users.AddRange(adminUser, testUser);

            // Add user roles
            var userRoles = new[]
            {
                new UserRole { UserId = "1", RoleId = "1" }, // Admin
                new UserRole { UserId = "2", RoleId = "2" }  // User
            };

            context.UserRoles.AddRange(userRoles);
        }
    }
}
