using Auth.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Infrastructure.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options):base(options)
        {
            
        }
        public DbSet<User> Users => Set<User>();
        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

        protected override void OnModelCreating(ModelBuilder mb)
        {
            mb.Entity<User>(e =>
            {
                e.HasKey(u => u.Id);
                e.Property(u => u.Email).HasMaxLength(256).IsRequired();
                e.HasIndex(u => u.Email).IsUnique();
                e.Property(u => u.PasswordHash).HasMaxLength(512).IsRequired();
                e.Property(u => u.FullName).HasMaxLength(128).IsRequired();
                e.Property(u => u.Role).HasMaxLength(32).IsRequired();
                e.Property(u => u.CreatedAt).IsRequired();
                e.Property(u => u.IsEmailVerified).IsRequired();
            });

            mb.Entity<RefreshToken>(e =>
            {
                e.HasKey(r => r.Id);
                e.HasIndex(r => r.Token).IsUnique();
                e.Property(r => r.Token).HasMaxLength(512).IsRequired();
                e.Property(r => r.CreatedByIp).HasMaxLength(64);

                // Quan hệ 1 User → nhiều RefreshToken
                e.HasOne(r => r.User)
                 .WithMany()
                 .HasForeignKey(r => r.UserId)
                 .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}
