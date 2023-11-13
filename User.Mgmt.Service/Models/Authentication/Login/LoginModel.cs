using System.ComponentModel.DataAnnotations;

namespace User.Mgmt.Service.Models.Authentication.Login
{
    public class LoginModel
    {
        [Required(ErrorMessage = "User Name Required")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Password Required")]
        public string Password { get; set; }
    }
}
