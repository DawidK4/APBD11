using JWT.Contexts;
using JWT.Model;
using Microsoft.EntityFrameworkCore;

namespace JWT.Services;

public interface IUserService
{
    Task SaveRefreshTokenAsync(string username, string refreshToken);
    Task<string> GetUsernameByRefreshTokenAsync(string refreshToken);
    Task<bool> IsUsernameUniqueAsync(string username);
    Task CreateUserAsync(string username, string passwordHash);
    Task<User> GetUserByUsernameAsync(string username);
}

public class UserService : IUserService
{
    private readonly DatabaseContext _context;
    
    public UserService(DatabaseContext context) 
    {
            _context = context; 
    }

        public async Task SaveRefreshTokenAsync(string username, string refreshToken)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user != null)
            {
                var existingRefreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.UserId == user.Id);
                if (existingRefreshToken != null)
                {
                    existingRefreshToken.Token = refreshToken;
                    existingRefreshToken.ExpiresAt = DateTime.UtcNow.AddDays(30);
                    existingRefreshToken.RevokedAt = null;
                }
                else
                {
                    var newRefreshToken = new RefreshToken
                    {
                        UserId = user.Id,
                        Token = refreshToken,
                        ExpiresAt = DateTime.UtcNow.AddDays(30),
                        CreatedAt = DateTime.UtcNow
                    };
                    _context.RefreshTokens.Add(newRefreshToken);
                }
                await _context.SaveChangesAsync();
            }
        }

        public async Task<string> GetUsernameByRefreshTokenAsync(string refreshToken)
        {
            var refreshTokenEntity = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == refreshToken);
            return refreshTokenEntity?.User?.Username;
        }

        public async Task<bool> IsUsernameUniqueAsync(string username)
        {
            return await _context.Users.AllAsync(u => u.Username != username);
        }

        public async Task CreateUserAsync(string username, string passwordHash)
        {
            try
            {
                var newUser = new User
                {
                    Username = username,
                    PasswordHash = passwordHash,
                    CreatedAt = DateTime.UtcNow
                };
                _context.Users.Add(newUser);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                // Log the exception for troubleshooting
                Console.WriteLine($"Error occurred while creating user: {ex.Message}");
                throw; // Re-throw the exception to propagate it further if necessary
            }
        }


        public async Task<User> GetUserByUsernameAsync(string username)
        {
            return await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            
        }
}
    