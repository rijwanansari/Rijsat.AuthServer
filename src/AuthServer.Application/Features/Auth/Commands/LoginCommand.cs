using AuthServer.Application.Common.Interfaces;
using AuthServer.Application.Common.Models;
using MediatR;

namespace AuthServer.Application.Features.Auth.Commands;

public record LoginCommand(string Username, string Password) : IRequest<AuthResult>;

public class LoginCommandHandler : IRequestHandler<LoginCommand, AuthResult>
{
    private readonly IAuthService _authService;

    public LoginCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<AuthResult> Handle(LoginCommand request, CancellationToken cancellationToken)
    {
        return await _authService.AuthenticateAsync(request.Username, request.Password);
    }
}
