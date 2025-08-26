using AuthServer.API.Models;
using AuthServer.Application.Common.Models;
using AuthServer.Application.Features.Auth.Commands;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;

    public AuthController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var result = await _mediator.Send(new LoginCommand(request.Username, request.Password));

        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors, message = result.Message });
        }

        return Ok(new
        {
            user = new
            {
                id = result.User!.Id,
                username = result.User.UserName,
                email = result.User.Email,
                firstName = result.User.FirstName,
                lastName = result.User.LastName
            },
            message = result.Message
        });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var result = await _mediator.Send(new RegisterCommand(request));

        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors, message = result.Message });
        }

        return Ok(new
        {
            user = new
            {
                id = result.User!.Id,
                username = result.User.UserName,
                email = result.User.Email,
                firstName = result.User.FirstName,
                lastName = result.User.LastName
            },
            message = result.Message
        });
    }
}
