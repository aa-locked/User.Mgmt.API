
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using User.Mgmt.Service.Models;

namespace User.Mgmt.API.Models
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            this.SeedRole(builder);
        }

        private void SeedRole(ModelBuilder builder)
        {
            builder.Entity<ApplicationRole>().HasData(

                new ApplicationRole() { Name = "Super-Admin", ConcurrencyStamp = "1", NormalizedName = "Super-Admin", LockPeriod = 380, AddedBy = "12558", LockPeriodAdd = 0 },
                new ApplicationRole() { Name = "IMS Admin", ConcurrencyStamp = "2", NormalizedName = "IMS Admin", LockPeriod = 5, AddedBy = "12558", LockPeriodAdd = 0 },
                new ApplicationRole() { Name = "Project Manager", ConcurrencyStamp = "3", NormalizedName = "Project Manager", LockPeriod = 1, AddedBy = "12558", LockPeriodAdd = 0 }
                );
        }
    }
}
