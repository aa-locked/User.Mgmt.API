using System.ComponentModel.DataAnnotations;

namespace User.Mgmt.Service.Models.Authentication.SignUp
{
    public class ResetPassword
    {
        public string Password { get; set; }
        [Compare("Password",ErrorMessage ="Password and Confirm Password does not match.")]
        public string ConfirmPassword { get; set; }
        public string Token { get; set; }
        public string Email { get; set; }
    }
}
