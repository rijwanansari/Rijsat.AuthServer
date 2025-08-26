namespace AuthServer.Application.Common.Models;

public class AuthCodeValidationResult
{
    public bool IsValid { get; set; }
    public string UserId { get; set; } = string.Empty;
    public List<string> Scopes { get; set; } = new();
    public string? ErrorCode { get; set; }
    public string? ErrorDescription { get; set; }

    public static AuthCodeValidationResult Success(string userId, IEnumerable<string> scopes)
    {
        return new AuthCodeValidationResult
        {
            IsValid = true,
            UserId = userId,
            Scopes = scopes.ToList()
        };
    }

    public static AuthCodeValidationResult Failure(string errorCode, string errorDescription)
    {
        return new AuthCodeValidationResult
        {
            IsValid = false,
            ErrorCode = errorCode,
            ErrorDescription = errorDescription
        };
    }
}
