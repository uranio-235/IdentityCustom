using IdentityCustom.Entity;

using Microsoft.EntityFrameworkCore;

namespace IdentityCustom.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<ApplicationUser> ApplicationUser { get; set; }
    public DbSet<ApplicationRoles> ApplicationRoles { get; set; }
}
