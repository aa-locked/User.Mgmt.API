using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.SignUp;

namespace User.Mgmt.Service.Services
{
    public interface IUserManagement
    {
       public  Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);
        public Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user);
        public Task<ApiResponse<string>> AssignClaimToUserAsync(List<UserClaim> roles, ApplicationUser user);
    }
}
