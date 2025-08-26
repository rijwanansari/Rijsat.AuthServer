using AuthServer.Application.Common.Interfaces;
using AuthServer.Application.Common.Models;
using AuthServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly IApplicationDbContext _context;
    private readonly IPasswordHasher _passwordHasher;

    public AuthService(IApplicationDbContext context, IPasswordHasher passwordHasher)
    {
        _context = context;
        _passwordHasher = passwordHasher;
    }

    public async Task<AuthResult> AuthenticateAsync(string username, string password)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => (u.UserName == username || u.Email == username) && u.IsActive);

        if (user == null)
            return AuthResult.Failure("Invalid username or password");

        if (!_passwordHasher.VerifyHashedPassword(user.PasswordHash, password))
            return AuthResult.Failure("Invalid username or password");

        if (user.LockoutEnabled && user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
            return AuthResult.Failure("Account is locked");

        // Reset failed attempts on successful login
        if (user.AccessFailedCount > 0)
        {
            user.AccessFailedCount = 0;
            await _context.SaveChangesAsync();
        }

        return AuthResult.Success(user);
    }

    public async Task<AuthResult> RegisterAsync(RegisterRequest request)
    {
        // Check if user already exists
        var existingUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == request.Email || u.UserName == request.Email);

        if (existingUser != null)
            return AuthResult.Failure("User already exists with this email");

        var user = new User
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            PhoneNumber = request.PhoneNumber,
            PasswordHash = _passwordHasher.HashPassword(request.Password),
            SecurityStamp = Guid.NewGuid().ToString(),
            EmailConfirmed = false, // In production, send confirmation email
            IsActive = true
        };

        _context.Users.Add(user);

        // Add user to default role
        var defaultRole = await _context.Roles
            .FirstOrDefaultAsync(r => r.Name == "User");

        if (defaultRole != null)
        {
            var userRole = new UserRole
            {
                UserId = user.Id,
                RoleId = defaultRole.Id
            };
            _context.UserRoles.Add(userRole);
        }

        await _context.SaveChangesAsync();

        return AuthResult.Success(user, "User registered successfully");
    }

    public async Task<AuthResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null || !user.IsActive)
            return AuthResult.Failure("User not found");

        if (!_passwordHasher.VerifyHashedPassword(user.PasswordHash, currentPassword))
            return AuthResult.Failure("Current password is incorrect");

        user.PasswordHash = _passwordHasher.HashPassword(newPassword);
        user.SecurityStamp = Guid.NewGuid().ToString();
        user.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        return AuthResult.Success(user, "Password changed successfully");
    }

    public async Task<bool> ValidateClientAsync(string clientId, string? clientSecret = null)
    {
        var client = await _context.Clients
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsActive);

        if (client == null)
            return false;

        // If client requires secret, validate it
        if (client.RequireClientSecret)
        {
            if (string.IsNullOrEmpty(clientSecret))
                return false;

            return _passwordHasher.VerifyHashedPassword(client.ClientSecretHash, clientSecret);
        }

        return true;
    }

    public async Task<string> GenerateAuthorizationCodeAsync(string userId, string clientId, string redirectUri,
        IEnumerable<string> scopes, string? codeChallenge = null, string? codeChallengeMethod = null)
    {
        var code = GenerateSecureRandomString(32);

        var authCode = new AuthorizationCode
        {
            Code = code,
            UserId = userId,
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scopes = string.Join(" ", scopes),
            ExpiresAt = DateTime.UtcNow.AddMinutes(5), // 5 minutes
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod
        };

        _context.AuthorizationCodes.Add(authCode);
        await _context.SaveChangesAsync();

        return code;
    }

    public async Task<AuthCodeValidationResult> ValidateAuthorizationCodeAsync(string code, string clientId,
        string redirectUri, string? codeVerifier = null)
    {
        var authCode = await _context.AuthorizationCodes
            .FirstOrDefaultAsync(ac => ac.Code == code && ac.ClientId == clientId &&
                                      ac.RedirectUri == redirectUri && !ac.IsUsed);

        if (authCode == null)
            return AuthCodeValidationResult.Failure("invalid_grant", "Invalid authorization code");

        if (authCode.IsExpired)
        {
            return AuthCodeValidationResult.Failure("invalid_grant", "Authorization code expired");
        }

        // Validate PKCE if present
        if (!string.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (string.IsNullOrEmpty(codeVerifier))
                return AuthCodeValidationResult.Failure("invalid_grant", "Code verifier required");

            var isValidChallenge = authCode.CodeChallengeMethod?.ToLower() switch
            {
                "s256" => authCode.CodeChallenge == GenerateCodeChallenge(codeVerifier),
                "plain" => authCode.CodeChallenge == codeVerifier,
                _ => false
            };

            if (!isValidChallenge)
                return AuthCodeValidationResult.Failure("invalid_grant", "Invalid code verifier");
        }

        // Mark as used
        authCode.IsUsed = true;
        authCode.UsedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return AuthCodeValidationResult.Success(authCode.UserId, authCode.Scopes.Split(' '));
    }

    private static string GenerateSecureRandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        using var rng = RandomNumberGenerator.Create();
        var result = new char[length];
        var buffer = new byte[sizeof(uint)];

        for (int i = 0; i < length; i++)
        {
            rng.GetBytes(buffer);
            var randomValue = BitConverter.ToUInt32(buffer, 0);
            result[i] = chars[(int)(randomValue % chars.Length)];
        }

        return new string(result);
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