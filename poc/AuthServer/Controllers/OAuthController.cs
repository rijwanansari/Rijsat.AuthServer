using AuthServer.Controllers.Request;
using AuthServer.Infrastructure;
using AuthServer.Models;
using AuthServer.Services.JwtTokenService;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Controllers
{
    [ApiController]
    [Route("oauth")]
    public class OAuthController(IJwtTokenService _tokenService,
        UserManager<ApplicationUser> _userManager,
        SignInManager<ApplicationUser> _signInManager,
        AuthDbContext _context,
        ILogger<OAuthController> _logger) : ControllerBase
    {
        [HttpPost("token")]
        public async Task<IActionResult> Token([FromForm] TokenRequest request)
        {
            try
            {
                return request.GrantType switch
                {
                    "password" => await HandlePasswordGrant(request),
                    //"authorization_code" => await HandleAuthorizationCodeGrant(request),
                    "refresh_token" => await HandleRefreshTokenGrant(request),
                    "client_credentials" => await HandleClientCredentialsGrant(request),
                    _ => BadRequest(new { error = "unsupported_grant_type" })
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing token request");
                return BadRequest(new { error = "invalid_request", error_description = ex.Message });
            }
        }

        private async Task<IActionResult> HandlePasswordGrant(TokenRequest request)
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
                return BadRequest(new { error = "invalid_request" });

            var user = await _userManager.FindByNameAsync(request.Username) ??
                    await _userManager.FindByEmailAsync(request.Username);

            if (user == null || !user.IsActive)
                return BadRequest(new { error = "invalid_grant" });

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
                return BadRequest(new { error = "invalid_grant" });

            var scopes = ParseScopes(request.Scope);
            var tokenResponse = await _tokenService.GenerateTokenAsync(user, request.ClientId ?? "default", scopes);

            return Ok(new
            {
                access_token = tokenResponse.AccessToken,
                refresh_token = tokenResponse.RefreshToken,
                token_type = tokenResponse.TokenType,
                expires_in = tokenResponse.ExpiresIn,
                scope = string.Join(" ", tokenResponse.Scopes)
            });
        }
        
        private async Task<IActionResult> HandleRefreshTokenGrant(TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken) || string.IsNullOrEmpty(request.ClientId))
            return BadRequest(new { error = "invalid_request" });

        // Validate client
        var client = await ValidateClientAsync(request.ClientId, request.ClientSecret);
        if (client == null)
            return BadRequest(new { error = "invalid_client" });

        var tokenResponse = await _tokenService.RefreshTokenAsync(request.RefreshToken, request.ClientId);

        return Ok(new
        {
            access_token = tokenResponse.AccessToken,
            refresh_token = tokenResponse.RefreshToken,
            token_type = tokenResponse.TokenType,
            expires_in = tokenResponse.ExpiresIn,
            scope = string.Join(" ", tokenResponse.Scopes)
        });
    }

    private async Task<IActionResult> HandleClientCredentialsGrant(TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.ClientId))
            return BadRequest(new { error = "invalid_request" });

        var client = await ValidateClientAsync(request.ClientId, request.ClientSecret);
        if (client == null)
            return BadRequest(new { error = "invalid_client" });

        // For client credentials, we create a service account or use a system user
        // For now, we'll create a minimal token without a user context
        var scopes = ParseScopes(request.Scope);
        
        // You might want to create a system user or handle this differently
        // For now, returning a basic client-only token
        return Ok(new
        {
            access_token = GenerateClientToken(client, scopes),
            token_type = "Bearer",
            expires_in = client.AccessTokenLifetime,
            scope = string.Join(" ", scopes)
        });
    }

    private async Task<ClientApplication?> ValidateClientAsync(string clientId, string? clientSecret)
    {
        var client = await _context.ClientApplications
            .Where(c => c.ClientId == clientId && c.IsActive)
            .FirstOrDefaultAsync();

        if (client == null) return null;

        // For public clients (like SPAs), secret might not be required
        if (!string.IsNullOrEmpty(client.ClientSecret) && !string.IsNullOrEmpty(clientSecret))
        {
            if (!BCrypt.Net.BCrypt.Verify(clientSecret, client.ClientSecret))
                return null;
        }

        return client;
    }

    private static List<string> ParseScopes(string? scope)
    {
        if (string.IsNullOrEmpty(scope))
            return new List<string> { "openid" };

        return scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    private string GenerateClientToken(ClientApplication client, List<string> scopes)
    {
        // This is a simplified implementation for client credentials
        // In a real scenario, you might want to create a more sophisticated token
        var claims = new List<System.Security.Claims.Claim>
        {
            new("client_id", client.ClientId),
            new("scope", string.Join(" ", scopes)),
            new(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, client.ClientId),
            new(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Use your JWT generation logic here
        // This would need to be implemented similarly to the user token generation
        return "client_token_placeholder"; // Implement actual token generation
    }

    [HttpPost("revoke")]
    public async Task<IActionResult> RevokeToken([FromForm] RevokeTokenRequest request)
    {
        if (string.IsNullOrEmpty(request.Token))
            return BadRequest(new { error = "invalid_request" });

        try
        {
            await _tokenService.RevokeRefreshTokenAsync(request.Token);
            return Ok();
        }
        catch
        {
            // Even if revocation fails, return success for security
            return Ok();
        }
    }

    }
}
