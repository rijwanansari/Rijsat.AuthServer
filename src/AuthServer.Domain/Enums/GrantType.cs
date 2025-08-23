namespace AuthServer.Domain.Enums;

public enum GrantType
{
    AuthorizationCode,
    ClientCredentials,
    ResourceOwnerPassword,
    RefreshToken,
    Implicit,
    Hybrid
}
