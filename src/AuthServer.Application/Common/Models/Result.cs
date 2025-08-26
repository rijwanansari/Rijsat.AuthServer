namespace AuthServer.Application.Common.Models;
public class Result<T>
{
    public bool IsSuccess { get; private set; }
    public T? Data { get; private set; }
    public string? ErrorCode { get; private set; }
    public string? ErrorDescription { get; private set; }
    public List<string> Errors { get; private set; } = new();

    private Result() { }

    public static Result<T> Success(T data)
    {
        return new Result<T> { IsSuccess = true, Data = data };
    }

    public static Result<T> Failure(string errorCode, string errorDescription)
    {
        return new Result<T>
        {
            IsSuccess = false,
            ErrorCode = errorCode,
            ErrorDescription = errorDescription
        };
    }

    public static Result<T> Failure(List<string> errors)
    {
        return new Result<T> { IsSuccess = false, Errors = errors };
    }
}