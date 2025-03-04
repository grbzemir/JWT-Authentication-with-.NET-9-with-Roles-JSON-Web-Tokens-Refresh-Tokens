using WT_Authentication.Entities;
using WT_Authentication.Models;

namespace WT_Authentication.Services
{
    public interface IAuthService
    {

        //Async await kullanacağım için task kullandım task işlemleri kuyruğa sokar ve işlemi gerçekleştirir
        Task<User?> RegisterAsync(UserDto request);
        Task<TokenResponseDto?> LoginAsync(UserDto request);
        Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
    }
}
