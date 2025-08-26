using AuthServer.Application.Common.Models;

namespace AuthServer.Application.Common.Interfaces;

public interface IAuthService
{
    Task<AuthResult> AuthenticateAsync(string username, string password);
    Task<AuthResult> RegisterAsync(RegisterRequest request);
    Task<AuthResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword);
    Task<bool> ValidateClientAsync(string clientId, string? clientSecret = null);
    Task<string> GenerateAuthorizationCodeAsync(string userId, string clientId, string redirectUri, IEnumerable<string> scopes, string? codeChallenge = null, string? codeChallengeMethod = null);
    Task<AuthCodeValidationResult> ValidateAuthorizationCodeAsync(string code, string clientId, string redirectUri, string? codeVerifier = null);
}
