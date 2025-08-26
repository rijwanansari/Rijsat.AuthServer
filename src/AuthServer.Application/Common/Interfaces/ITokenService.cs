using AuthServer.Application.Common.Models;
using AuthServer.Domain.Entities;

namespace AuthServer.Application.Common.Interfaces;

public interface ITokenService
{
    Task<TokenResponse> GenerateTokensAsync(User user, Client client, IEnumerable<string> scopes);
    Task<TokenResponse> RefreshTokenAsync(string refreshToken, string clientId);
    Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null);
    Task<bool> RevokeAllUserTokensAsync(string userId, string? clientId = null);
    Task CleanupExpiredTokensAsync();
}
