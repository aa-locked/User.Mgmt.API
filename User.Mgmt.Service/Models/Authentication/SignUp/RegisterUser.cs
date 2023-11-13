using System.ComponentModel.DataAnnotations;

namespace User.Mgmt.Service.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "User First Name is required!")]
        [MaxLength(50)]
        public string UsrFN { get; set; }
        [Required(ErrorMessage = "User Last Name is required!")]
        [MaxLength(50)]
        public string UsrLN { get; set; }
        [Required(ErrorMessage = "User Code is required!")]
        public string UsrCode { get; set; }
        [Required(ErrorMessage = "User Name is required!")]
        public string UserName { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "User Name is required!")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required!")]
        public string Password { get; set; }
        [Required(ErrorMessage = "Password is required!")]
        public List<string> Roles { get; set; }
    }
}
