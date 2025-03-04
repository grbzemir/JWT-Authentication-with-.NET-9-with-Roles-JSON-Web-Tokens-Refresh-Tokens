﻿using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WT_Authentication.Database;
using WT_Authentication.Entities;
using WT_Authentication.Models;

namespace WT_Authentication.Services
{
    public class AuthService(UserDbContext context , IConfiguration configuration) : IAuthService
    {
        public async Task<string?> LoginAsync(UserDto request)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);


            if (user is null)
            {
                return null;
            }

            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return null;
            }

          
            return CreateToken(user);
        }

        public async Task<User?> RegisterAsync(UserDto request)
        {
            if(await context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return null;
            }

            var user = new User();
            //Request istek atma işlemi request ile userDto'ya
            //istek atıyorum istek başarılı olursa User nesnesi döner
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);

            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            context.Users.Add(user);
            await context.SaveChangesAsync();

            return user;
        }

        private string CreateToken(User user)
        {
            //Kullanıcı hakkında bilgileri olusturma
            var claims = new List<Claim>
            {
                //ClaimTypes.Name = Kullanıcı adı tokene ekliyoruz
                new Claim(ClaimTypes.Name , user.Username),
                new Claim(ClaimTypes.NameIdentifier , user.Id.ToString())
            };

            //Güvenlik Anahtarı oluşturma
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            //HmacSha256 şifreleme algoritması SigningCredentials: Token'ın güvenliğini sağlamak için kullanılır.
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //issuer: Token’ı oluşturan servisin adresini belirtir (appsettings.json içinden alınır).
            //audience: Token’ı hangi servislerin kabul edeceğini belirler.
            //claims: Token içerisine eklenen kullanıcı bilgilerini içerir.
            //expires: Token’ın ne zaman süresinin dolacağını belirtir(1 gün sonra geçersiz olacak).
            //signingCredentials: Token’ın imzalama ve güvenlik bilgilerini içerir.
            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
                );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
