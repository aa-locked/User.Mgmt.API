using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace User.Mgmt.Service.Models.Authentication.SignUp
{
    public class CreateUserResponse
    {
        public string Token { get; set; }
        public ApplicationUser User { get; set; }
    }
}
