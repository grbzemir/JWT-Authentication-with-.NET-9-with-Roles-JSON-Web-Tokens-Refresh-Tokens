using WT_Authentication.Entities;
using WT_Authentication.Models;

namespace WT_Authentication.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<string?> LoginAsync(UserDto request);
    }
}
