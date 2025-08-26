using AuthServer.API.Models;
using AuthServer.Application.Common.Models;
using AuthServer.Application.Features.Tokens.Commands;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.API.Controllers
{
    [Route("api/[controller]")]
    [Route("oauth")]
    public class OAuthController : ControllerBase
    {
        private readonly IMediator _mediator;

        public OAuthController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpPost("token")]
        public async Task<IActionResult> Token([FromForm] TokenRequest request)
        {
            var result = await _mediator.Send(new GenerateTokenCommand(request));

            if (!result.IsSuccess)
            {
                return BadRequest(new
                {
                    error = result.ErrorCode,
                    error_description = result.ErrorDescription
                });
            }

            var tokenResponse = result.Data!;
            return Ok(new
            {
                access_token = tokenResponse.AccessToken,
                refresh_token = tokenResponse.RefreshToken,
                token_type = tokenResponse.TokenType,
                expires_in = tokenResponse.ExpiresIn,
                scope = tokenResponse.Scope
            });
        }

        [HttpPost("revoke")]
        public async Task<IActionResult> RevokeToken([FromForm] RevokeTokenRequest request)
        {
            // Implementation for token revocation
            return Ok();
        }
    }
}
