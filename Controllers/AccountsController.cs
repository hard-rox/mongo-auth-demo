using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace MongoAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<ApplicationRole> roleManager;

        public AccountsController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<ApplicationRole> roleManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
        }

        [HttpPost("signup")]
        public async Task<IActionResult> Signup(string email, string password)
        {
            var user = new ApplicationUser()
            {
                UserName = email,
                Email = email
            };
            var result = await userManager.CreateAsync(user, password);
            if (!result.Succeeded) return BadRequest(result.Errors);

            var roleRes = await userManager.AddToRoleAsync(user, "Admin");
            if (!roleRes.Succeeded) return BadRequest(roleRes.Errors);

            return Ok();
        }

        [HttpPost("signin")]
        public async Task<IActionResult> Signin(string email, string password)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user == null || !await userManager.CheckPasswordAsync(user, password))
                return BadRequest("Password not matched.");

            var roles = await userManager.GetRolesAsync(user);
            var claims = new List<Claim>()
            {
                    new Claim(ClaimTypes.Email, email),
                    new Claim(JwtRegisteredClaimNames.Jti, user.Id.ToString())
            };
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("6FDAFD81C19920ED01042F440C5A406146B10F09CAD8A0EF721A453E714F574B"));

            var token = new JwtSecurityToken(
                issuer: "localhost",
                audience: "aud",
                expires: DateTime.Now.AddHours(24),
                claims: claims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return Ok(new JwtSecurityTokenHandler().WriteToken(token));
        }

        [Authorize]
        [HttpPost("roles")]
        public async Task<IActionResult> AddRole(string roleName)
        {
            var role = new ApplicationRole()
            {
                Name = roleName
            };
            var result = await roleManager.CreateAsync(role);
            if (result.Succeeded) return Ok();
            return BadRequest(result.Errors);
        }

        [Authorize]
        [HttpGet("roles")]
        public IActionResult GetRoles()
        {
            var roles = roleManager.Roles.ToList();
            return Ok(roles);
        }

        [Authorize]
        [HttpGet("users")]
        public IActionResult GetUsers()
        {
            var users = userManager.Users.ToList();
            return Ok(users);
        }
    }
}
