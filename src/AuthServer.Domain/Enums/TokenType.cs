namespace AuthServer.Domain;

public enum TokenType
{
    AccessToken,
    RefreshToken,
    AuthorizationCode,
    IdToken
}
