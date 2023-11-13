using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace User.Mgmt.Service.Models
{
    public class ApplicationRole : IdentityRole
    {
        public int LockPeriod { get; set; }
        public bool ActStatus { get; set; } = true;
        [MaxLength(10)]
        public string AddedBy { get; set; }
        public DateTime AddedOn { get; set; } = DateTime.Now;
        public int LockPeriodAdd { get; set; } = 0;
    }
}
