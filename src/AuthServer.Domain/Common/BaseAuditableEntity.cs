namespace AuthServer.Domain.Common;

public abstract class BaseAuditableEntity : BaseEntity
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
}
