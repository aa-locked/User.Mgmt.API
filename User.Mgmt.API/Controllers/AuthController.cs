
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Mgmt.API.Models;
using User.Mgmt.Service.Models;
using User.Mgmt.Service.Models.Authentication.Login;
using User.Mgmt.Service.Models.Authentication.SignUp;
using User.Mgmt.Service.Services;

namespace User.Mgmt.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailServices _emailServices;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IUserManagement _userManagement;

        public AuthController(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager
                            , IConfiguration configuration, IEmailServices emailServices
                            , SignInManager<ApplicationUser> signInManager
                            , IUserManagement userManagement)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailServices = emailServices;
            _signInManager = signInManager;
            _userManagement = userManagement;
        }

        [HttpPost]
        public async Task<IActionResult> RegisterUser([FromBody] RegisterUser registerUser)
        {

            var tokenResponse = await _userManagement.CreateUserWithTokenAsync(registerUser);

            if (tokenResponse.IsSuccess == true)
            {
                List<UserClaim> usrClaims = new List<UserClaim>() { new UserClaim {
                    ClaimType="IsGetAuth",
                    ClaimValue="IsGetAuth"
                }
                };
                await _userManagement.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);
                await _userManagement.AssignClaimToUserAsync(usrClaims, tokenResponse.Response.User);

                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth", new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme); //Auth is a controller name
                var message = new Message(new string[] { registerUser.Email }, "Confirmation Email", confirmationLink);
                _emailServices.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                           new Response { status = "success", message = "User Created Successfully!", IsSuccess = true });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                           new Response { status = "error", message = "User Not Created !", IsSuccess = false });

        }
        //To Send Email
        [HttpGet]
        public IActionResult TestEmail()
        {


            var msg = new Message(new string[] { "amishra@balajeegroup.com", "opandey@balajeegroup.com", "vgautam@balajeegroup.com" }, "Testing", "hello maam");
            _emailServices.SendEmail(msg);
            return StatusCode(StatusCodes.Status200OK,
                        new Response { status = "success", message = "Mail Send Successfully!" });
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { status = "success", message = "Email Verified Succesfully!" });
                }

            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                       new Response { status = "error", message = "Email Not Verified!" });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> LoginUser([FromBody] LoginModel loginModel)
        {
            //Check Username
            var user = await _userManager.FindByNameAsync(loginModel.UserName);

            //Check Password
            if (user != null)
            {
                var passcheck = await _userManager.CheckPasswordAsync(user, loginModel.Password);
                if (passcheck == true)
                {
                    //Claimlist Creation

                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                };
                    //adding claims to user
                    var userClaims = await _userManager.GetClaimsAsync(user);
                    authClaims.AddRange(userClaims);
                    //Getting User Roles
                    var userRole = await _userManager.GetRolesAsync(user);
                    //Add Role to the list
                    foreach (var role in userRole)
                    {
                        //Adding Roles to the claim list
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                        
                        var usrRole = await _roleManager.FindByNameAsync(role);
                        if (usrRole != null)
                        {
                            //Get all the claims against the role and add to claim list
                            var roleClaims = await _roleManager.GetClaimsAsync(usrRole);
                            foreach (Claim roleClaim in roleClaims)
                            {
                                authClaims.Add(roleClaim);
                            }
                        }
                    }

                   
                   
                    

                    if (user.TwoFactorEnabled == true)
                    {
                        await _signInManager.SignOutAsync();
                        await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, false);
                        var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                        var msg = new Message(new string[] { user.Email, "dubeyaalok12@gmail.com" }, "OTP confirmation", token);
                        _emailServices.SendEmail(msg);

                        return StatusCode(StatusCodes.Status200OK,
                            new Response { status = "success", message = "OTP Sent To Your Verified Email " + user.Email + " Succesfully!" });

                    }

                    //generate token with the claim
                    var jwtToken = GetToken(authClaims);

                    //returning token
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    });
                }
                return Unauthorized();
            }
            return Unauthorized();
        }

        private JwtSecurityToken GetToken(List<Claim> authClaim)
        {
            var authsigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: authClaim,
                signingCredentials: new SigningCredentials(authsigningKey, SecurityAlgorithms.HmacSha256)

                );
            return token;
        }
        [HttpPost]
        [Route("loginWithOTP")]
        public async Task<IActionResult> LogInWithOTP(string OTP, string UserName)
        {
            if (OTP != null)
            {
                var user = await _userManager.FindByNameAsync(UserName);
                var signIn = await _signInManager.TwoFactorSignInAsync("Email", OTP, false, false);
                if (signIn.Succeeded)
                {
                    if (UserName != null)
                    {
                        var authClaims = new List<Claim>
                          {
                                new Claim(ClaimTypes.Name,user.UserName),
                                  new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                           };
                        var userRole = await _userManager.GetRolesAsync(user);
                        //Add Role to the list
                        foreach (var role in userRole)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, role));
                        }
                        var jwtToken = GetToken(authClaims);

                        //returning token
                        return Ok(new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                            expiration = jwtToken.ValidTo
                        });
                    }
                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                       new Response { status = "error", message = "Something Gets Wrong!" });
        }
        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string Email)
        {
            var user = await _userManager.FindByEmailAsync(Email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotpassLink = Url.Action(nameof(ResetPassword), "Auth", new { token, Email = user.Email }, Request.Scheme);
                var msg = new Message(new string[] { user.Email, "adubey@balajeegroup.com" }, "Confirmation Email Link", forgotpassLink!);
                _emailServices.SendEmail(msg);
                return StatusCode(StatusCodes.Status200OK,
                      new Response { status = "success", message = "Forgot Password Mail Sent Successfully!" });
            }
            return StatusCode(StatusCodes.Status404NotFound,
                      new Response { status = "error", message = "Something Gets Wrong!" });
        }
        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new { model });
        }


        [HttpPost]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var restpasswordresult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);

                if (!restpasswordresult.Succeeded)
                {
                    foreach (var errors in restpasswordresult.Errors)
                    {
                        ModelState.AddModelError(errors.Code, errors.Description);
                    }
                    return Ok(ModelState);
                }

                return StatusCode(StatusCodes.Status200OK,
                      new Response { status = "success", message = "Forgot Password Mail Sent Successfully!" });
            }
            return StatusCode(StatusCodes.Status404NotFound,
                      new Response { status = "error", message = "Something Gets Wrong!" });
        }

    }
}
