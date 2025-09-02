using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthServer.Infrastructure;
using AuthServer.Models;
using AuthServer.Services.JwtTokenService.Response;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Services.JwtTokenService;

public class JwtTokenService(IConfiguration _configuration,
    AuthDbContext _context,
    ILogger<JwtTokenService> _logger,
    UserManager<ApplicationUser> _userManager,
    RoleManager<ApplicationRole> _roleManager) : IJwtTokenService
{
    public async Task<TokenResponse> GenerateTokenAsync(ApplicationUser user, string clientId, List<string> scopes)
    {
        var client = await _context.ClientApplications.FindAsync(clientId);
        if (client == null)
            throw new ArgumentException("Invalid client");

        var claims = await BuildClaimsAsync(user, scopes);
        var accessToken = GenerateAccessToken(claims, client.AccessTokenLifetime);
        var refreshToken = await GenerateRefreshTokenAsync(user.Id, clientId, client.RefreshTokenLifetime);

        // Update user last login
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = client.AccessTokenLifetime,
            Scopes = scopes
        };
    }

    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken, string clientId)
    {
        var storedToken = await _context.RefreshTokens
            .Where(rt => rt.Token == refreshToken && rt.ClientId == clientId && !rt.IsRevoked)
            .FirstOrDefaultAsync();

        if (storedToken == null || storedToken.ExpiryDate < DateTime.UtcNow)
            throw new SecurityTokenException("Invalid refresh token");

        var user = await _userManager.FindByIdAsync(storedToken.UserId);
        if (user == null || !user.IsActive)
            throw new SecurityTokenException("User not found or inactive");

        var client = await _context.ClientApplications.FindAsync(clientId);
        if (client == null)
            throw new ArgumentException("Invalid client");

        // Revoke old refresh token
        storedToken.IsRevoked = true;
        
        // Generate new tokens
        var scopes = new List<string> { "openid", "profile", "email", "api" }; // You might want to store scopes with refresh token
        var claims = await BuildClaimsAsync(user, scopes);
        var accessToken = GenerateAccessToken(claims, client.AccessTokenLifetime);
        var newRefreshToken = await GenerateRefreshTokenAsync(user.Id, clientId, client.RefreshTokenLifetime);

        await _context.SaveChangesAsync();

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshToken,
            ExpiresIn = client.AccessTokenLifetime,
            Scopes = scopes
        };
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"] ?? throw new InvalidOperationException("JWT Secret not configured"));
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["JwtSettings:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["JwtSettings:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
            return principal;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Token validation failed");
            return null;
        }
    }

    public async Task RevokeRefreshTokenAsync(string refreshToken)
    {
        var storedToken = await _context.RefreshTokens
            .Where(rt => rt.Token == refreshToken)
            .FirstOrDefaultAsync();

        if (storedToken != null)
        {
            storedToken.IsRevoked = true;
            await _context.SaveChangesAsync();
        }
    }

    public async Task<string> GenerateAuthorizationCodeAsync(string userId, string clientId, string redirectUri, List<string> scopes, string? codeChallenge = null, string? codeChallengeMethod = null)
    {
        var code = GenerateRandomString(32);
        var authCode = new AuthorizationCode
        {
            Code = code,
            UserId = userId,
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scope = string.Join(" ", scopes),
            ExpiryDate = DateTime.UtcNow.AddMinutes(10), // 10 minutes
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod
        };

        _context.AuthorizationCodes.Add(authCode);
        await _context.SaveChangesAsync();

        return code;
    }

    public async Task<AuthCodeValidationResult> ValidateAuthorizationCodeAsync(string code, string clientId, string redirectUri, string? codeVerifier = null)
    {
        var authCode = await _context.AuthorizationCodes
            .Where(ac => ac.Code == code && ac.ClientId == clientId && ac.RedirectUri == redirectUri && !ac.IsUsed)
            .FirstOrDefaultAsync();

        if (authCode == null)
            return new AuthCodeValidationResult { IsValid = false, ErrorMessage = "Invalid authorization code" };

        if (authCode.ExpiryDate < DateTime.UtcNow)
        {
            return new AuthCodeValidationResult { IsValid = false, ErrorMessage = "Authorization code expired" };
        }

        // Validate PKCE if present
        if (!string.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (string.IsNullOrEmpty(codeVerifier))
                return new AuthCodeValidationResult { IsValid = false, ErrorMessage = "Code verifier required" };

            var isValidChallenge = authCode.CodeChallengeMethod?.ToLower() switch
            {
                "s256" => authCode.CodeChallenge == GenerateCodeChallenge(codeVerifier),
                "plain" => authCode.CodeChallenge == codeVerifier,
                _ => false
            };

            if (!isValidChallenge)
                return new AuthCodeValidationResult { IsValid = false, ErrorMessage = "Invalid code verifier" };
        }

        // Mark as used
        authCode.IsUsed = true;
        await _context.SaveChangesAsync();

        return new AuthCodeValidationResult
        {
            IsValid = true,
            UserId = authCode.UserId,
            Scopes = authCode.Scope.Split(' ').ToList()
        };
    }

    private async Task<List<Claim>> BuildClaimsAsync(ApplicationUser user, List<string> scopes)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new(JwtRegisteredClaimNames.EmailVerified, user.EmailConfirmed.ToString().ToLower()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (scopes.Contains("profile"))
        {
            claims.Add(new Claim("name", $"{user.FirstName} {user.LastName}".Trim()));
            claims.Add(new Claim("given_name", user.FirstName ?? ""));
            claims.Add(new Claim("family_name", user.LastName ?? ""));
            claims.Add(new Claim("preferred_username", user.UserName ?? ""));
        }

        // Add roles
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
            claims.Add(new Claim("role", role));
        }

        // Add permissions
        var userPermissions = await GetUserPermissionsAsync(user.Id);
        foreach (var permission in userPermissions)
        {
            claims.Add(new Claim("permission", permission));
        }

        return claims;
    }

    private string GenerateAccessToken(List<Claim> claims, int lifetimeSeconds)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"] ?? throw new InvalidOperationException()));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["JwtSettings:Issuer"],
            audience: _configuration["JwtSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(lifetimeSeconds),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private async Task<string> GenerateRefreshTokenAsync(string userId, string clientId, int lifetimeSeconds)
    {
        var token = GenerateRandomString(64);
        var refreshToken = new RefreshToken
        {
            UserId = userId,
            ClientId = clientId,
            Token = token,
            ExpiryDate = DateTime.UtcNow.AddSeconds(lifetimeSeconds)
        };

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();

        return token;
    }

    private async Task<List<string>> GetUserPermissionsAsync(string userId)
    {
        var permissions = new List<string>();

        // Get permissions from roles
        var userRoles = await _context.UserRoles
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.RoleId)
            .ToListAsync();

        var rolePermissions = await _context.RolePermissions
            .Where(rp => userRoles.Contains(rp.RoleId))
            .Include(rp => rp.Permission)
            .Select(rp => rp.Permission!.Name)
            .ToListAsync();

        permissions.AddRange(rolePermissions);

        // Get direct user permissions
        var userPermissions = await _context.UserPermissions
            .Where(up => up.UserId == userId && up.IsGranted)
            .Include(up => up.Permission)
            .Select(up => up.Permission!.Name)
            .ToListAsync();

        permissions.AddRange(userPermissions);

        return permissions.Distinct().ToList();
    }

    private static string GenerateRandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var random = new Random();
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

}
