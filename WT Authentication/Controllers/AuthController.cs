using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WT_Authentication.Entities;
using WT_Authentication.Models;

namespace WT_Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public static User user = new();

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)

        {
            //Request istek atma işlemi request ile userDto'ya
            //istek atıyorum istek başarılı olursa User nesnesi döner
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user , request.Password);

            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            return Ok(user);
        }

    }
}
