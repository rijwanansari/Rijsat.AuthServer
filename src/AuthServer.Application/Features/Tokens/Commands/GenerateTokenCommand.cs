using AuthServer.Application.Common.Interfaces;
using AuthServer.Application.Common.Models;
using MediatR;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Security.Claims; // Add this using

namespace AuthServer.Application.Features.Tokens.Commands;

public record GenerateTokenCommand(TokenRequest Request) : IRequest<Result<TokenResponse>>;

public class GenerateTokenCommandHandler : IRequestHandler<GenerateTokenCommand, Result<TokenResponse>>
{
    private readonly IAuthService _authService;
    private readonly ITokenService _tokenService;
    private readonly IApplicationDbContext _context;
    private readonly IJwtService _jwtService; // Add this field

    public GenerateTokenCommandHandler(
        IAuthService authService,
        ITokenService tokenService,
        IApplicationDbContext context,
        IJwtService jwtService) // Add this parameter
    {
        _authService = authService;
        _tokenService = tokenService;
        _context = context;
        _jwtService = jwtService; // Assign here
    }

    public async Task<Result<TokenResponse>> Handle(GenerateTokenCommand request, CancellationToken cancellationToken)
    {
        var tokenRequest = request.Request;

        return tokenRequest.GrantType.ToLower() switch
        {
            "password" => await HandlePasswordGrantAsync(tokenRequest),
            "authorization_code" => await HandleAuthorizationCodeGrantAsync(tokenRequest),
            "refresh_token" => await HandleRefreshTokenGrantAsync(tokenRequest),
            "client_credentials" => await HandleClientCredentialsGrantAsync(tokenRequest),
            _ => Result<TokenResponse>.Failure("unsupported_grant_type", "The grant type is not supported")
        };
    }

    private async Task<Result<TokenResponse>> HandlePasswordGrantAsync(TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            return Result<TokenResponse>.Failure("invalid_request", "Username and password are required");

        if (!await _authService.ValidateClientAsync(request.ClientId ?? "", request.ClientSecret))
            return Result<TokenResponse>.Failure("invalid_client", "Client authentication failed");

        var authResult = await _authService.AuthenticateAsync(request.Username, request.Password);
        if (!authResult.Succeeded || authResult.User == null)
            return Result<TokenResponse>.Failure("invalid_grant", "Invalid username or password");

        var client = await _context.Clients
            .FirstOrDefaultAsync(c => c.ClientId == request.ClientId, cancellationToken: default);

        if (client == null)
            return Result<TokenResponse>.Failure("invalid_client", "Client not found");

        var scopes = ParseScopes(request.Scope);
        var tokenResponse = await _tokenService.GenerateTokensAsync(authResult.User, client, scopes);

        return Result<TokenResponse>.Success(tokenResponse);
    }

    private async Task<Result<TokenResponse>> HandleAuthorizationCodeGrantAsync(TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.ClientId))
            return Result<TokenResponse>.Failure("invalid_request", "Code and client_id are required");

        if (!await _authService.ValidateClientAsync(request.ClientId, request.ClientSecret))
            return Result<TokenResponse>.Failure("invalid_client", "Client authentication failed");

        var codeValidation = await _authService.ValidateAuthorizationCodeAsync(
            request.Code, request.ClientId, request.RedirectUri ?? "", request.CodeVerifier);

        if (!codeValidation.IsValid)
            return Result<TokenResponse>.Failure(codeValidation.ErrorCode ?? "invalid_grant", codeValidation.ErrorDescription ?? "Invalid authorization code");

        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == codeValidation.UserId, cancellationToken: default);

        if (user == null || !user.IsActive)
            return Result<TokenResponse>.Failure("invalid_grant", "User not found or inactive");

        var client = await _context.Clients
            .FirstOrDefaultAsync(c => c.ClientId == request.ClientId, cancellationToken: default);

        if (client == null)
            return Result<TokenResponse>.Failure("invalid_client", "Client not found");

        var tokenResponse = await _tokenService.GenerateTokensAsync(user, client, codeValidation.Scopes);
        return Result<TokenResponse>.Success(tokenResponse);
    }

    private async Task<Result<TokenResponse>> HandleRefreshTokenGrantAsync(TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken) || string.IsNullOrEmpty(request.ClientId))
            return Result<TokenResponse>.Failure("invalid_request", "Refresh token and client_id are required");

        if (!await _authService.ValidateClientAsync(request.ClientId, request.ClientSecret))
            return Result<TokenResponse>.Failure("invalid_client", "Client authentication failed");

        try
        {
            var tokenResponse = await _tokenService.RefreshTokenAsync(request.RefreshToken, request.ClientId);
            return Result<TokenResponse>.Success(tokenResponse);
        }
        catch (SecurityException ex)
        {
            return Result<TokenResponse>.Failure("invalid_grant", ex.Message);
        }
    }

    private async Task<Result<TokenResponse>> HandleClientCredentialsGrantAsync(TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.ClientId))
            return Result<TokenResponse>.Failure("invalid_request", "Client_id is required");

        if (!await _authService.ValidateClientAsync(request.ClientId, request.ClientSecret))
            return Result<TokenResponse>.Failure("invalid_client", "Client authentication failed");

        var client = await _context.Clients
            .FirstOrDefaultAsync(c => c.ClientId == request.ClientId, cancellationToken: default);

        if (client == null)
            return Result<TokenResponse>.Failure("invalid_client", "Client not found");

        // For client credentials, create a system/service user or handle without user context
        var scopes = ParseScopes(request.Scope);

        // Generate access token without user context (client-only token)
        var claims = new List<Claim>
        {
            new("client_id", client.ClientId),
            new("scope", string.Join(" ", scopes)),
            new(JwtRegisteredClaimNames.Sub, client.ClientId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        var accessToken = _jwtService.GenerateAccessToken(claims, TimeSpan.FromSeconds(client.AccessTokenLifetime));

        return Result<TokenResponse>.Success(new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = client.AccessTokenLifetime,
            Scope = string.Join(" ", scopes)
        });
    }

    private static IEnumerable<string> ParseScopes(string? scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
            return new[] { "openid" };

        return scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }
}