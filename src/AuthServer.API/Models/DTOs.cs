using System.ComponentModel.DataAnnotations;

namespace AuthServer.API.Models;

public class LoginRequest
{
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}

public class RevokeTokenRequest
{
    [Required]
    public string Token { get; set; } = string.Empty;

    public string? TokenTypeHint { get; set; }
}

public class AuthorizeRequest
{
    public string? ResponseType { get; set; }
    public string? ClientId { get; set; }
    public string? RedirectUri { get; set; }
    public string? Scope { get; set; }
    public string? State { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public string? Nonce { get; set; }
}

