using AuthServer.Application.Features.Users.Queries;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthServer.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UsersController : ControllerBase
    {
        private readonly IMediator _mediator;

        public UsersController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpGet("me")]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                         ?? User.FindFirst("sub")?.Value;

            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var user = await _mediator.Send(new GetCurrentUserQuery(userId));

            if (user == null)
                return NotFound();

            return Ok(new
            {
                id = user.Id,
                username = user.UserName,
                email = user.Email,
                firstName = user.FirstName,
                lastName = user.LastName,
                isActive = user.IsActive,
                createdAt = user.CreatedAt,
                lastLoginAt = user.LastLoginAt,
                roles = User.Claims
                    .Where(c => c.Type == "role")
                    .Select(c => c.Value)
                    .ToList(),
                permissions = User.Claims
                    .Where(c => c.Type == "permission")
                    .Select(c => c.Value)
                    .ToList()
            });
        }

        [HttpGet]
        [Authorize(Policy = "CanReadUsers")]
        public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
        {
            var skip = (page - 1) * pageSize;
            var users = await _mediator.Send(new GetUsersQuery(skip, pageSize));

            return Ok(new
            {
                users = users.Select(u => new
                {
                    id = u.Id,
                    username = u.UserName,
                    email = u.Email,
                    firstName = u.FirstName,
                    lastName = u.LastName,
                    isActive = u.IsActive,
                    createdAt = u.CreatedAt,
                    lastLoginAt = u.LastLoginAt
                }),
                page,
                pageSize
            });
        }
    }
}
