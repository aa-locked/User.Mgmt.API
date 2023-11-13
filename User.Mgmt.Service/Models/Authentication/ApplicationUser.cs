using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace User.Mgmt.Service.Models
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(50)]
        public string UsrCode { get; set; }
        [MaxLength(50)]
        public string UsrFN { get; set; }
        [MaxLength(50)]
        public string UsrLN { get; set; }
        public bool ActStatus { get; set; } = true;
        [MaxLength(10)]
        public string AddedBy { get; set; }
        public DateTime AddedOn { get; set; } = DateTime.Now;
    }
}
