using AuthServer.Domain.Entities;
using AuthServer.Infrastructure.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace AuthServer.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = "AdminOnly")]
public class ClientsController : ControllerBase
{
    private readonly ApplicationDbContext _context;

    public ClientsController(ApplicationDbContext context)
    {
        _context = context;
    }

    // POST: api/clients
    [HttpPost]
    public async Task<IActionResult> RegisterClient([FromBody] RegisterClientRequest request)
    {
        if (await _context.Clients.AnyAsync(c => c.ClientId == request.ClientId))
            return BadRequest(new { error = "ClientId already exists" });

        var client = new Client
        {
            ClientId = request.ClientId,
            ClientName = request.ClientName,
            Description = request.Description,
            ClientSecretHash = HashSecret(request.ClientSecret),
            RequireClientSecret = true,
            IsActive = true,
            AllowedGrantTypes = request.AllowedGrantTypes ?? "authorization_code",
            RedirectUris = request.RedirectUris ?? string.Empty,
            PostLogoutRedirectUris = request.PostLogoutRedirectUris ?? string.Empty,
            AllowedCorsOrigins = request.AllowedCorsOrigins ?? string.Empty,
            RequirePkce = request.RequirePkce,
            AllowPlainTextPkce = request.AllowPlainTextPkce,
            RequireConsent = request.RequireConsent,
            AllowRememberConsent = request.AllowRememberConsent,
            AllowOfflineAccess = request.AllowOfflineAccess,
            AccessTokenLifetime = request.AccessTokenLifetime ?? 3600,
            RefreshTokenLifetime = request.RefreshTokenLifetime ?? 2592000,
            AuthorizationCodeLifetime = request.AuthorizationCodeLifetime ?? 300
        };
        _context.Clients.Add(client);
        await _context.SaveChangesAsync();
        return Ok(new { clientId = client.ClientId, clientName = client.ClientName });
    }

    // GET: api/clients
    [HttpGet]
    public async Task<IActionResult> GetClients()
    {
        var clients = await _context.Clients
            .Select(c => new {
                c.ClientId,
                c.ClientName,
                c.Description,
                c.IsActive,
                c.AllowedGrantTypes,
                c.RedirectUris,
                c.AllowedCorsOrigins
            })
            .ToListAsync();
        return Ok(clients);
    }

    // Utility: Hash client secret
    private static string HashSecret(string secret)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(bytes);
    }
}

public class RegisterClientRequest
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string ClientSecret { get; set; } = string.Empty;
    public string? AllowedGrantTypes { get; set; }
    public string? RedirectUris { get; set; }
    public string? PostLogoutRedirectUris { get; set; }
    public string? AllowedCorsOrigins { get; set; }
    public bool RequirePkce { get; set; } = true;
    public bool AllowPlainTextPkce { get; set; } = false;
    public bool RequireConsent { get; set; } = false;
    public bool AllowRememberConsent { get; set; } = true;
    public bool AllowOfflineAccess { get; set; } = false;
    public int? AccessTokenLifetime { get; set; }
    public int? RefreshTokenLifetime { get; set; }
    public int? AuthorizationCodeLifetime { get; set; }
}
