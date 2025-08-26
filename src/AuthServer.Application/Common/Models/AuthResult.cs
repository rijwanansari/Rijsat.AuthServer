using AuthServer.Domain.Entities;

namespace AuthServer.Application.Common.Models;

public class AuthResult
{
    public bool Succeeded { get; set; }
    public User? User { get; set; }
    public List<string> Errors { get; set; } = new();
    public string? Message { get; set; }

    public static AuthResult Success(User user, string? message = null)
    {
        return new AuthResult { Succeeded = true, User = user, Message = message };
    }

    public static AuthResult Failure(params string[] errors)
    {
        return new AuthResult { Succeeded = false, Errors = errors.ToList() };
    }

    public static AuthResult Failure(List<string> errors, string? message = null)
    {
        return new AuthResult { Succeeded = false, Errors = errors, Message = message };
    }
}
