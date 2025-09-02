using System;
using AuthServer.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Infrastructure;

public class AuthDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    { 
        
    }
    public DbSet<ClientApplication> ClientApplications { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<Permission> Permissions { get; set; }
    public DbSet<RolePermission> RolePermissions { get; set; }
    public DbSet<UserPermission> UserPermissions { get; set; }
    public DbSet<Scope> Scopes { get; set; }
    public DbSet<ClientScope> ClientScopes { get; set; }
    public DbSet<AuthorizationCode> AuthorizationCodes { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure table names
        builder.Entity<ApplicationUser>().ToTable("Users");
        builder.Entity<ApplicationRole>().ToTable("Roles");

        // Configure relationships
        builder.Entity<RolePermission>()
            .HasKey(rp => new { rp.RoleId, rp.PermissionId });

        builder.Entity<UserPermission>()
            .HasKey(up => new { up.UserId, up.PermissionId });

        builder.Entity<ClientScope>()
            .HasKey(cs => new { cs.ClientId, cs.ScopeName });

        builder.Entity<ClientApplication>()
            .HasKey(c => c.ClientId);

        builder.Entity<Scope>()
            .HasKey(s => s.Name);

        builder.Entity<AuthorizationCode>()
            .HasKey(ac => ac.Code);

        // Configure indexes
        builder.Entity<RefreshToken>()
            .HasIndex(rt => rt.Token)
            .IsUnique();

        builder.Entity<RefreshToken>()
            .HasIndex(rt => rt.ExpiryDate);

        builder.Entity<AuthorizationCode>()
            .HasIndex(ac => ac.ExpiryDate);

        // Seed data
        SeedData(builder);
    }
    
    private void SeedData(ModelBuilder builder)
    {
        // Seed roles
        builder.Entity<ApplicationRole>().HasData(
            new ApplicationRole
            {
                Id = "1",
                Name = "Admin",
                NormalizedName = "ADMIN",
                Description = "System Administrator",
                CreatedAt = new DateTime(2025, 08, 08)
            },
            new ApplicationRole
            {
                Id = "2", 
                Name = "User",
                NormalizedName = "USER",
                Description = "Standard User",
                CreatedAt = new DateTime(2025, 08, 08)
            },
            new ApplicationRole
            {
                Id = "3",
                Name = "Manager", 
                NormalizedName = "MANAGER",
                Description = "Manager Role",
                CreatedAt = new DateTime(2025, 08, 08)
            }
        );
        
        // Seed permissions
        builder.Entity<Permission>().HasData(
            new Permission { Id = 1, Name = "users.read", Description = "Read users", Category = "Users" },
            new Permission { Id = 2, Name = "users.write", Description = "Write users", Category = "Users" },
            new Permission { Id = 3, Name = "users.delete", Description = "Delete users", Category = "Users" },
            new Permission { Id = 4, Name = "roles.read", Description = "Read roles", Category = "Roles" },
            new Permission { Id = 5, Name = "roles.write", Description = "Write roles", Category = "Roles" },
            new Permission { Id = 6, Name = "api.read", Description = "Read API", Category = "API" },
            new Permission { Id = 7, Name = "api.write", Description = "Write API", Category = "API" }
        );
        
        // Seed scopes
        builder.Entity<Scope>().HasData(
            new Scope { Name = "openid", DisplayName = "OpenID", Description = "OpenID Connect" },
            new Scope { Name = "profile", DisplayName = "Profile", Description = "User profile information" },
            new Scope { Name = "email", DisplayName = "Email", Description = "User email address" },
            new Scope { Name = "api", DisplayName = "API Access", Description = "Access to protected APIs" },
            new Scope { Name = "offline_access", DisplayName = "Offline Access", Description = "Refresh token access" }
        );
        
        // // Seed client application
        // builder.Entity<ClientApplication>().HasData(
        //     new ClientApplication
        //     {
        //         ClientId = "web-app",
        //         ClientName = "Web Application",
        //         ClientSecret = BCrypt.Net.BCrypt.HashPassword("web-app-secret"),
        //         Description = "Main web application client",
        //         AllowedGrantTypes = "authorization_code,refresh_token",
        //         RedirectUris = "https://localhost:5002/signin-callback,https://localhost:5002/callback",
        //         AllowedScopes = "openid,profile,email,api,offline_access",
        //         AccessTokenLifetime = 3600,
        //         RefreshTokenLifetime = 2592000
        //     }
        // );
    }
}
