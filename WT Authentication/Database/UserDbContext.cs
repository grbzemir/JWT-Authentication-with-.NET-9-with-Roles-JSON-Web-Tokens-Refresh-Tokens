using Microsoft.EntityFrameworkCore;
using WT_Authentication.Entities;

namespace WT_Authentication.Database
{
    public class UserDbContext:DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options):base(options)
        {
            
        }

        public DbSet<User> Users { get; set; }
       
    }
}
