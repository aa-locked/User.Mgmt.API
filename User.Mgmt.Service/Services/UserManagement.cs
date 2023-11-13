
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Data;
using System;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.SignUp;
using System.Security.Claims;

namespace User.Mgmt.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailServices _emailServices;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public UserManagement(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager
                            , IConfiguration configuration, IEmailServices emailServices
                            , SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailServices = emailServices;
            _signInManager = signInManager;
        }



        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            //check user
            var usr = await _userManager.FindByEmailAsync(registerUser.Email);
            if (usr != null)
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 403, Message = "User Already Exists" };
            }
            //create User
            ApplicationUser usrcreat = new()
            {
                UsrCode = registerUser.UsrCode,
                UsrFN = registerUser.UsrFN,
                UsrLN = registerUser.UsrLN,
                ActStatus = true,
                AddedBy = "12558",
                AddedOn = DateTime.Now,
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                TwoFactorEnabled = true//For two factor authntication

            };
            var rslt = await _userManager.CreateAsync(usrcreat, registerUser.Password);
            if (!rslt.Succeeded)
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 500, Message = "User Failed To Create" };
            }
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(usrcreat);
            return new ApiResponse<CreateUserResponse> { IsSuccess = true, StatusCode = 201, Message = "User Created", Response = new CreateUserResponse() { User = usrcreat, Token = token } };
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user)
        {
            var assignedRole = new List<string>();
            foreach (var item in roles)
            {
                if (await _roleManager.RoleExistsAsync(item))
                {
                    if (!await _userManager.IsInRoleAsync(user, item))
                    {
                        await _userManager.AddToRoleAsync(user, item);
                        assignedRole.Add(item);
                    }

                }
            }
            return new ApiResponse<List<string>> { IsSuccess = true, StatusCode = 200, Message = "Roles has been assigned", Response = assignedRole };

        }

        public async Task<ApiResponse<string>> AssignClaimToUserAsync(List<UserClaim> claims, ApplicationUser user)
        {
            var assignedClaim = new List<string>();
            var claimresult = await _userManager.GetClaimsAsync(user);
            var result = await _userManager.RemoveClaimsAsync(user, claimresult);
            await _userManager.AddClaimsAsync(user, claims.Select(x => new Claim(x.ClaimType,x.ClaimValue)));  
            return new ApiResponse<string> { IsSuccess = true, StatusCode = 200, Message = "Roles has been assigned", Response = "Claims Inserted Successfully" };
        }
    }
}
