using AuthServer.API.Models;
using AuthServer.Application.Common.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace AuthServer.API.Controllers
{
    [ApiController]
    [Route("oauth")]
    public class AuthorizeController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IApplicationDbContext _context;

        public AuthorizeController(IAuthService authService, IApplicationDbContext context)
        {
            _authService = authService;
            _context = context;
        }

        [HttpGet("authorize")]
        public async Task<IActionResult> Authorize([FromQuery] AuthorizeRequest request)
        {
            // Validate required parameters
            if (string.IsNullOrEmpty(request.ClientId) ||
                string.IsNullOrEmpty(request.RedirectUri) ||
                string.IsNullOrEmpty(request.ResponseType))
            {
                return BadRequest(new { error = "invalid_request", error_description = "Missing required parameters" });
            }

            // Validate client
            if (!await _authService.ValidateClientAsync(request.ClientId))
            {
                return BadRequest(new { error = "invalid_client", error_description = "Invalid client" });
            }

            // Validate redirect URI
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ClientId == request.ClientId);

            if (client == null)
            {
                return BadRequest(new { error = "invalid_client" });
            }

            var allowedUris = client.RedirectUris.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (!allowedUris.Contains(request.RedirectUri))
            {
                return BadRequest(new { error = "invalid_request", error_description = "Invalid redirect URI" });
            }

            // For API-only server, return the authorization URL for frontend to handle
            // In a full implementation, this would show a consent page
            return Ok(new
            {
                authUrl = $"/oauth/authorize?{HttpContext.Request.QueryString}",
                clientName = client.ClientName,
                scopes = request.Scope?.Split(' ') ?? new[] { "openid" },
                requiresConsent = client.RequireConsent
            });
        }

        [HttpPost("authorize")]
        [Authorize]
        public async Task<IActionResult> AuthorizePost([FromForm] AuthorizeRequest request)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                         ?? User.FindFirst("sub")?.Value;

            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            // Generate authorization code
            var scopes = request.Scope?.Split(' ') ?? new[] { "openid" };
            var code = await _authService.GenerateAuthorizationCodeAsync(
                userId,
                request.ClientId!,
                request.RedirectUri!,
                scopes,
                request.CodeChallenge,
                request.CodeChallengeMethod);

            var redirectUrl = $"{request.RedirectUri}?code={code}";
            if (!string.IsNullOrEmpty(request.State))
                redirectUrl += $"&state={request.State}";

            return Ok(new { redirectUrl });
        }
    }
}
