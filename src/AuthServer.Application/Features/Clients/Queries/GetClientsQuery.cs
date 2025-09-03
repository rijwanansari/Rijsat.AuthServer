using AuthServer.Application.Common.Interfaces;
using AuthServer.Domain.Entities;
using MediatR;
using Microsoft.EntityFrameworkCore;

public class GetClientsQuery : IRequest<IEnumerable<ClientDto>> { }

public class ClientDto
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsActive { get; set; }
    public string AllowedGrantTypes { get; set; } = string.Empty;
    public string RedirectUris { get; set; } = string.Empty;
    public string AllowedCorsOrigins { get; set; } = string.Empty;
}

public class GetClientsQueryHandler : IRequestHandler<GetClientsQuery, IEnumerable<ClientDto>>
{
    private readonly IApplicationDbContext _context;
    public GetClientsQueryHandler(IApplicationDbContext context)
    {
        _context = context;
    }
    public async Task<IEnumerable<ClientDto>> Handle(GetClientsQuery query, CancellationToken cancellationToken)
    {
        return await _context.Clients
            .Select(c => new ClientDto
            {
                ClientId = c.ClientId,
                ClientName = c.ClientName,
                Description = c.Description,
                IsActive = c.IsActive,
                AllowedGrantTypes = c.AllowedGrantTypes,
                RedirectUris = c.RedirectUris,
                AllowedCorsOrigins = c.AllowedCorsOrigins
            })
            .ToListAsync(cancellationToken);
    }
}
