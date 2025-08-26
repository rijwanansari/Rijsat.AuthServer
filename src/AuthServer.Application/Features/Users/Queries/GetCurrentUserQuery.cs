using AuthServer.Application.Common.Interfaces;
using AuthServer.Domain.Entities;
using MediatR;

namespace AuthServer.Application.Features.Users.Queries;

public record GetCurrentUserQuery(string UserId) : IRequest<User?>;

public class GetCurrentUserQueryHandler : IRequestHandler<GetCurrentUserQuery, User?>
{
    private readonly IUserService _userService;

    public GetCurrentUserQueryHandler(IUserService userService)
    {
        _userService = userService;
    }

    public async Task<User?> Handle(GetCurrentUserQuery request, CancellationToken cancellationToken)
    {
        return await _userService.GetByIdAsync(request.UserId);
    }
}