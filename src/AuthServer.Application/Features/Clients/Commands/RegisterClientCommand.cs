using AuthServer.Application.Common.Interfaces;
using AuthServer.Application.Common.Models;
using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

public class RegisterClientCommand : IRequest<RegisterClientResult>
{
    public RegisterClientRequest Request { get; }
    public RegisterClientCommand(RegisterClientRequest request) => Request = request;
}

public class RegisterClientResult
{
    public bool Succeeded { get; set; }
    public Client? Client { get; set; }
    public string? Message { get; set; }
    public IEnumerable<string>? Errors { get; set; }
}

public class RegisterClientCommandHandler : IRequestHandler<RegisterClientCommand, RegisterClientResult>
{
    private readonly IApplicationDbContext _context;
    public RegisterClientCommandHandler(IApplicationDbContext context)
    {
        _context = context;
    }
    public async Task<RegisterClientResult> Handle(RegisterClientCommand command, CancellationToken cancellationToken)
    {
        var req = command.Request;
        if (await _context.Clients.AnyAsync(c => c.ClientId == req.ClientId, cancellationToken))
        {
            return new RegisterClientResult { Succeeded = false, Message = "ClientId already exists", Errors = new[] { "ClientId already exists" } };
        }
        var client = new Client
        {
            ClientId = req.ClientId,
            ClientName = req.ClientName,
            Description = req.Description,
            ClientSecretHash = HashSecret(req.ClientSecret),
            RequireClientSecret = true,
            IsActive = true,
            AllowedGrantTypes = req.AllowedGrantTypes ?? "authorization_code",
            RedirectUris = req.RedirectUris ?? string.Empty,
            PostLogoutRedirectUris = req.PostLogoutRedirectUris ?? string.Empty,
            AllowedCorsOrigins = req.AllowedCorsOrigins ?? string.Empty,
            RequirePkce = req.RequirePkce,
            AllowPlainTextPkce = req.AllowPlainTextPkce,
            RequireConsent = req.RequireConsent,
            AllowRememberConsent = req.AllowRememberConsent,
            AllowOfflineAccess = req.AllowOfflineAccess,
            AccessTokenLifetime = req.AccessTokenLifetime ?? 3600,
            RefreshTokenLifetime = req.RefreshTokenLifetime ?? 2592000,
            AuthorizationCodeLifetime = req.AuthorizationCodeLifetime ?? 300
        };
        _context.Clients.Add(client);
        await _context.SaveChangesAsync(cancellationToken);
        return new RegisterClientResult { Succeeded = true, Client = client, Message = "Client registered successfully" };
    }
    private static string HashSecret(string secret)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(bytes);
    }
}
