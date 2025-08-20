using System;
using System.Security.Claims;
using AuthServer.Models;
using AuthServer.Services.JwtTokenService.Response;

namespace AuthServer.Services.JwtTokenService;

public interface IJwtTokenService
{
    Task<TokenResponse> GenerateTokenAsync(ApplicationUser user, string clientId, List<string> scopes);
    Task<TokenResponse> RefreshTokenAsync(string refreshToken, string clientId);
    ClaimsPrincipal? ValidateToken(string token);
    Task RevokeRefreshTokenAsync(string refreshToken);
    Task<string> GenerateAuthorizationCodeAsync(string userId, string clientId, string redirectUri, List<string> scopes, string? codeChallenge = null, string? codeChallengeMethod = null);
    Task<AuthCodeValidationResult> ValidateAuthorizationCodeAsync(string code, string clientId, string redirectUri, string? codeVerifier = null);
}
