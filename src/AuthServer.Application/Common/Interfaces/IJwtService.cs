using System.Security.Claims;

namespace AuthServer.Application.Common.Interfaces;

public interface IJwtService
{
    string GenerateAccessToken(IEnumerable<Claim> claims, TimeSpan? expiry = null);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token, bool validateLifetime = true);
    string? GetClaimFromToken(string token, string claimType);
    bool IsTokenExpired(string token);
}
