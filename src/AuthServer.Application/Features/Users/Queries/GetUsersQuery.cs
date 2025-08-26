using AuthServer.Application.Common.Interfaces;
using AuthServer.Domain.Entities;
using MediatR;

namespace AuthServer.Application.Features.Users.Queries;

public record GetUsersQuery(int Skip = 0, int Take = 50) : IRequest<IEnumerable<User>>;

public class GetUsersQueryHandler : IRequestHandler<GetUsersQuery, IEnumerable<User>>
{
    private readonly IUserService _userService;

    public GetUsersQueryHandler(IUserService userService)
    {
        _userService = userService;
    }

    public async Task<IEnumerable<User>> Handle(GetUsersQuery request, CancellationToken cancellationToken)
    {
        return await _userService.GetUsersAsync(request.Skip, request.Take);
    }
}
