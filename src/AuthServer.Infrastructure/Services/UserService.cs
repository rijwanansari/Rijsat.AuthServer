using AuthServer.Application.Common.Interfaces;
using AuthServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Infrastructure.Services;

public class UserService : IUserService
{
    private readonly IApplicationDbContext _context;
    private readonly IPasswordHasher _passwordHasher;

    public UserService(IApplicationDbContext context, IPasswordHasher passwordHasher)
    {
        _context = context;
        _passwordHasher = passwordHasher;
    }

    public async Task<User?> GetByIdAsync(string id)
    {
        return await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Id == id);
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<User?> GetByUsernameAsync(string username)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.UserName == username);
    }

    public async Task<IEnumerable<User>> GetUsersAsync(int skip = 0, int take = 50)
    {
        return await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .OrderBy(u => u.CreatedAt)
            .Skip(skip)
            .Take(take)
            .ToListAsync();
    }

    public async Task<bool> CreateUserAsync(User user, string password)
    {
        try
        {
            user.PasswordHash = _passwordHasher.HashPassword(password);
            user.SecurityStamp = Guid.NewGuid().ToString();

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> UpdateUserAsync(User user)
    {
        try
        {
            user.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> DeleteUserAsync(string id)
    {
        try
        {
            var user = await _context.Users.FindAsync(id);
            if (user != null)
            {
                user.IsDeleted = true;
                user.UpdatedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> SetUserActiveAsync(string id, bool isActive)
    {
        try
        {
            var user = await _context.Users.FindAsync(id);
            if (user != null)
            {
                user.IsActive = isActive;
                user.UpdatedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    public async Task<IEnumerable<string>> GetUserRolesAsync(string userId)
    {
        return await _context.UserRoles
            .Where(ur => ur.UserId == userId)
            .Include(ur => ur.Role)
            .Select(ur => ur.Role!.Name)
            .ToListAsync();
    }

    public async Task<bool> AddUserToRoleAsync(string userId, string roleName)
    {
        try
        {
            var role = await _context.Roles
                .FirstOrDefaultAsync(r => r.Name == roleName);

            if (role == null) return false;

            var existingUserRole = await _context.UserRoles
                .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == role.Id);

            if (existingUserRole == null)
            {
                var userRole = new UserRole
                {
                    UserId = userId,
                    RoleId = role.Id
                };

                _context.UserRoles.Add(userRole);
                await _context.SaveChangesAsync();
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> RemoveUserFromRoleAsync(string userId, string roleName)
    {
        try
        {
            var role = await _context.Roles
                .FirstOrDefaultAsync(r => r.Name == roleName);

            if (role == null) return false;

            var userRole = await _context.UserRoles
                .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == role.Id);

            if (userRole != null)
            {
                _context.UserRoles.Remove(userRole);
                await _context.SaveChangesAsync();
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<IEnumerable<Permission>> GetUserPermissionsAsync(string userId)
    {
        var rolePermissions = await _context.UserRoles
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role!.RolePermissions)
            .Select(rp => rp.Permission!)
            .ToListAsync();

        var userPermissions = await _context.UserPermissions
            .Where(up => up.UserId == userId && up.IsGranted)
            .Select(up => up.Permission!)
            .ToListAsync();

        return rolePermissions.Union(userPermissions).DistinctBy(p => p.Id);
    }
}


