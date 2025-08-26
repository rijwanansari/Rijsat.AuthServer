using AuthServer.Application.Common.Interfaces;
using AuthServer.Application.Common.Models;
using AuthServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security;
using System.Security.Claims;

namespace AuthServer.Infrastructure.Services;

public class TokenService : ITokenService
{
    private readonly IApplicationDbContext _context;
    private readonly IJwtService _jwtService;

    public TokenService(IApplicationDbContext context, IJwtService jwtService)
    {
        _context = context;
        _jwtService = jwtService;
    }

    public async Task<TokenResponse> GenerateTokensAsync(User user, Client client, IEnumerable<string> scopes)
    {
        var scopeList = scopes.ToList();

        // Build claims
        var claims = await BuildClaimsAsync(user, scopeList);

        // Generate tokens
        var accessToken = _jwtService.GenerateAccessToken(claims, TimeSpan.FromSeconds(client.AccessTokenLifetime));
        var refreshToken = _jwtService.GenerateRefreshToken();

        // Store refresh token
        var refreshTokenEntity = new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            ClientId = client.ClientId,
            Scopes = string.Join(" ", scopeList),
            ExpiresAt = DateTime.UtcNow.AddSeconds(client.RefreshTokenLifetime)
        };

        _context.RefreshTokens.Add(refreshTokenEntity);
        await _context.SaveChangesAsync();

        // Update user last login
        user.LastLoginAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            ExpiresIn = client.AccessTokenLifetime,
            Scope = string.Join(" ", scopeList)
        };
    }

    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken, string clientId)
    {
        var storedToken = await _context.RefreshTokens
            .Include(rt => rt.User)
            .Include(rt => rt.Client)
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.ClientId == clientId);

        if (storedToken == null || !storedToken.IsActive)
            throw new SecurityException("Invalid refresh token");

        if (storedToken.User == null || !storedToken.User.IsActive)
            throw new SecurityException("User not found or inactive");

        if (storedToken.Client == null || !storedToken.Client.IsActive)
            throw new SecurityException("Client not found or inactive");

        // Revoke old refresh token
        storedToken.IsRevoked = true;
        storedToken.RevokedAt = DateTime.UtcNow;

        // Generate new tokens
        var scopes = storedToken.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var newTokenResponse = await GenerateTokensAsync(storedToken.User, storedToken.Client, scopes);

        await _context.SaveChangesAsync();

        return newTokenResponse;
    }

    public async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null)
    {
        // Try to revoke as refresh token first
        var refreshToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == token && !rt.IsRevoked);

        if (refreshToken != null)
        {
            refreshToken.IsRevoked = true;
            refreshToken.RevokedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return true;
        }

        // Could also implement access token blacklisting here
        return false;
    }

    public async Task<bool> RevokeAllUserTokensAsync(string userId, string? clientId = null)
    {
        var query = _context.RefreshTokens.Where(rt => rt.UserId == userId && !rt.IsRevoked);

        if (!string.IsNullOrEmpty(clientId))
            query = query.Where(rt => rt.ClientId == clientId);

        var tokens = await query.ToListAsync();

        foreach (var token in tokens)
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();
        return tokens.Any();
    }

    public async Task CleanupExpiredTokensAsync()
    {
        var expiredRefreshTokens = await _context.RefreshTokens
            .Where(rt => rt.ExpiresAt < DateTime.UtcNow)
            .ToListAsync();

        var expiredAuthCodes = await _context.AuthorizationCodes
            .Where(ac => ac.ExpiresAt < DateTime.UtcNow)
            .ToListAsync();

        _context.RefreshTokens.RemoveRange(expiredRefreshTokens);
        _context.AuthorizationCodes.RemoveRange(expiredAuthCodes);

        await _context.SaveChangesAsync();
    }

    private async Task<List<Claim>> BuildClaimsAsync(User user, List<string> scopes)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (scopes.Contains("openid"))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.EmailVerified, user.EmailConfirmed.ToString().ToLower()));
        }

        if (scopes.Contains("profile"))
        {
            claims.Add(new Claim("name", user.FullName));
            claims.Add(new Claim("given_name", user.FirstName ?? ""));
            claims.Add(new Claim("family_name", user.LastName ?? ""));
            claims.Add(new Claim("preferred_username", user.UserName));
        }

        // Add roles
        var userRoles = await _context.UserRoles
            .Include(ur => ur.Role)
            .Where(ur => ur.UserId == user.Id && ur.Role!.IsActive)
            .Select(ur => ur.Role!.Name)
            .ToListAsync();

        foreach (var role in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
            claims.Add(new Claim("role", role));
        }

        // Add permissions
        var permissions = await GetUserPermissionsAsync(user.Id);
        foreach (var permission in permissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        return claims;
    }

    private async Task<List<string>> GetUserPermissionsAsync(string userId)
    {
        var permissions = new List<string>();

        // Get permissions from roles
        var rolePermissions = await _context.UserRoles
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role!.RolePermissions)
            .Select(rp => rp.Permission!.Name)
            .ToListAsync();

        permissions.AddRange(rolePermissions);

        // Get direct user permissions
        var userPermissions = await _context.UserPermissions
            .Where(up => up.UserId == userId && up.IsGranted)
            .Select(up => up.Permission!.Name)
            .ToListAsync();

        permissions.AddRange(userPermissions);

        return permissions.Distinct().ToList();
    }
}

