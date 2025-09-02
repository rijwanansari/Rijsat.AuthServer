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
    [Route("api/auth")]
    [ApiController]
    public class AuthorizeController(
        UserManager<ApplicationUser> _userManager,
        SignInManager<ApplicationUser> _signInManager,
        IJwtTokenService _tokenService,
        AuthDbContext _context,
        ILogger<AuthorizeController> _logger
        ) : ControllerBase
    {
        [HttpGet("authorize")]
        public async Task<IActionResult> Authorize([FromQuery] AuthorizeRequest request)
        {
            // Validate request parameters
            if (string.IsNullOrEmpty(request.ClientId) || string.IsNullOrEmpty(request.RedirectUri))
                return BadRequest("Invalid request parameters");

            // Validate client
            var client = await _context.ClientApplications
                .Where(c => c.ClientId == request.ClientId && c.IsActive)
                .FirstOrDefaultAsync();

            if (client == null)
                return BadRequest("Invalid client");

            // Validate redirect URI
            var allowedUris = client.RedirectUris.Split(',', StringSplitOptions.RemoveEmptyEntries);
            if (!allowedUris.Contains(request.RedirectUri))
                return BadRequest("Invalid redirect URI");

            // Check if user is authenticated
            if (!_signInManager.IsSignedIn(User))
            {
                // Store the authorization request and redirect to login
                //TempData["AuthorizeRequest"] = System.Text.Json.JsonSerializer.Serialize(request);
                return RedirectToAction("Login", "Account", new { returnUrl = Url.Action("Authorize", "Authorize") });
            }

            // User is authenticated, show consent page or generate code
            var user = await _userManager.GetUserAsync(User);
            if (user == null || !user.IsActive)
            {
                await _signInManager.SignOutAsync();
                return RedirectToAction("Login", "Account");
            }

            // For demonstration, auto-consent (in production, show consent page)
            return await GenerateAuthorizationResponse(request, user);
        }
        private async Task<IActionResult> GenerateAuthorizationResponse(AuthorizeRequest request, ApplicationUser user)
        {
            var scopes = request.Scope?.Split(' ').ToList() ?? new List<string> { "openid" };

            try
            {
                if (request.ResponseType == "code")
                {
                    // Generate authorization code
                    var code = await _tokenService.GenerateAuthorizationCodeAsync(
                        user.Id,
                        request.ClientId!,
                        request.RedirectUri!,
                        scopes,
                        request.CodeChallenge,
                        request.CodeChallengeMethod);

                    var redirectUrl = $"{request.RedirectUri}?code={code}";
                    if (!string.IsNullOrEmpty(request.State))
                        redirectUrl += $"&state={request.State}";

                    return Redirect(redirectUrl);
                }

                return BadRequest("Unsupported response type");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating authorization response");
                var errorUrl = $"{request.RedirectUri}?error=server_error";
                if (!string.IsNullOrEmpty(request.State))
                    errorUrl += $"&state={request.State}";

                return Redirect(errorUrl);
            }
        }
    
    }
}
