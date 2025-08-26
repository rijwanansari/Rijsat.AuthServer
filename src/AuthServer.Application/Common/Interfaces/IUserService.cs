using AuthServer.Domain.Entities;

namespace AuthServer.Application.Common.Interfaces;

public interface IUserService
{
    Task<User?> GetByIdAsync(string id);
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByUsernameAsync(string username);
    Task<IEnumerable<User>> GetUsersAsync(int skip = 0, int take = 50);
    Task<bool> CreateUserAsync(User user, string password);
    Task<bool> UpdateUserAsync(User user);
    Task<bool> DeleteUserAsync(string id);
    Task<bool> SetUserActiveAsync(string id, bool isActive);
    Task<IEnumerable<string>> GetUserRolesAsync(string userId);
    Task<bool> AddUserToRoleAsync(string userId, string roleName);
    Task<bool> RemoveUserFromRoleAsync(string userId, string roleName);
    Task<IEnumerable<Permission>> GetUserPermissionsAsync(string userId);
}
