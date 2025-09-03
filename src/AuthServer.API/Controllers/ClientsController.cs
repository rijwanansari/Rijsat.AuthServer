using AuthServer.Application.Common.Models;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = "AdminOnly")]
public class ClientsController : ControllerBase
{
    private readonly IMediator _mediator;

    public ClientsController(IMediator mediator)
    {
        _mediator = mediator;
    }

    // POST: api/clients
    [HttpPost]
    public async Task<IActionResult> RegisterClient([FromBody] RegisterClientRequest request)
    {
        var result = await _mediator.Send(new RegisterClientCommand(request));
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors, message = result.Message });
        }
        return Ok(new { clientId = result.Client!.ClientId, clientName = result.Client.ClientName, message = result.Message });
    }

    // GET: api/clients
    [HttpGet]
    public async Task<IActionResult> GetClients()
    {
        var clients = await _mediator.Send(new GetClientsQuery());
        return Ok(clients);
    }
}


