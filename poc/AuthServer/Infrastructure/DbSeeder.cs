using System;
using AuthServer.Models;

namespace AuthServer.Infrastructure;

public static class DbSeeder
{
    public static void Seed(AuthDbContext db)
    {
        if (!db.ClientApplications.Any(c => c.ClientId == "web-app"))
        {
            db.ClientApplications.Add(new ClientApplication
            {
                ClientId = "web-app",
                ClientName = "Web Application",
                ClientSecret = BCrypt.Net.BCrypt.HashPassword("web-app-secret"),
                Description = "Main web application client",
                AllowedGrantTypes = "authorization_code,refresh_token",
                RedirectUris = "https://localhost:5002/signin-callback,https://localhost:5002/callback",
                AllowedScopes = "openid,profile,email,api,offline_access",
                AccessTokenLifetime = 3600,
                RefreshTokenLifetime = 2592000
            });
            db.SaveChanges();
        }
    }
}

