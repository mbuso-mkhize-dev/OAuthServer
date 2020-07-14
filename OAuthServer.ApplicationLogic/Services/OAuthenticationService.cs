using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using OAuthServer.ApplicationLogic.Entities;
using OAuthServer.ApplicationLogic.Interfaces;
using OAuthServer.EntityFramework.Core.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OAuthServer.ApplicationLogic.Services
{
    public class OAuthenticationService : IOAuthenticationService
    {
        private readonly JwtSettingsEntity _jwtSettings;
        private readonly SignInManager<User> _signInManager;
        //private readonly UserManager<IdentityUser> _userManager;
        //private readonly RoleManager<IdentityRole> _roleManager;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly IUserService _userService;

        public OAuthenticationService(
            JwtSettingsEntity jwtSettings,
            IUserService userService,
            SignInManager<User> signInManager,
           // RoleManager<IdentityRole> roleManager,
            TokenValidationParameters tokenValidationParameters)
           // UserManager<IdentityUser> userManager)
        {
            _jwtSettings = jwtSettings;
            _userService = userService;
            _signInManager = signInManager;
           // _roleManager = roleManager;
            _tokenValidationParameters = tokenValidationParameters;
           // _userManager = userManager;
        }

        public async Task<AuthenticationResult> AuthenticateUserAsync(UserEntity userEntity)
        {
            var result = await _signInManager.PasswordSignInAsync(userEntity.Email, userEntity.Password, false, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return await GetTokenByEmail(userEntity.Email);
            }

            return null;
        }

        private async Task<AuthenticationResult> GetTokenByEmail(string email)
        {
            var user = _userService.GetUserByEmail(email);
            var principal = await _signInManager.CreateUserPrincipalAsync(user);

            return GenerateAccessToken(principal);
        }

        private AuthenticationResult GenerateAccessToken(ClaimsPrincipal principal)
        {
            var ticket = new AuthenticationTicket(principal,
                new AuthenticationProperties(),
                IdentityConstants.ApplicationScheme);

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = ticket.Principal.Claims;
            //var claims = new[] {
            //    new Claim(JwtRegisteredClaimNames.Sub, userInfo.Username),
            //    new Claim(JwtRegisteredClaimNames.Email, userInfo.Email),
            //    //new Claim("DateOfJoing", userInfo.DateOfJoing.ToString("yyyy-MM-dd")),
            //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            //};

            var token = new JwtSecurityToken(_jwtSettings.Issuer,
                _jwtSettings.Issuer,
                claims,
                expires: DateTime.Now.AddSeconds(_jwtSettings.TokenLifeTimeInSecs), // move to app settings
                signingCredentials: credentials);

            var refreshToken = new JwtSecurityToken(_jwtSettings.Issuer,
                _jwtSettings.Issuer,
                new List<Claim> { claims.FirstOrDefault(c => c.Type == "Email") } ,
                expires: DateTime.Now.AddSeconds(_jwtSettings.RefreshTokenLifeTimeInSecs), 
                signingCredentials: credentials);

            var accessToken =  new JwtSecurityTokenHandler().WriteToken(token);

            var _refreshToken = new JwtSecurityTokenHandler().WriteToken(refreshToken);

            return new AuthenticationResult
            {
                Token = accessToken,
                RefreshToken = _refreshToken,
                Success = true
            };
        }

        public async Task<AuthenticationResult> AuthenticateUserFromRefreshToken(string token)
        {
            var email = Authenticate(token);
            var authResult = await GetTokenByEmail(email);
            return authResult;
        }

        private string Authenticate(string token)
        {
            var validator = new JwtSecurityTokenHandler();

            if (validator.CanReadToken(token))
            {
                try
                {
                    // This line throws if invalid
                    var principal = validator.ValidateToken(token, _tokenValidationParameters, out SecurityToken validatedToken);

                    // If we got here then the token is valid
                    if (principal.HasClaim(c => c.Type == "Email"))
                    {
                        return principal.Claims.Where(c => c.Type == "Email").First().Value;
                    }
                }
                catch (Exception e)
                {
                    throw e;
                }
            }

            return string.Empty;
        }

        //public async Task<AuthenticationResult> RegisterAsync(string email, string password)
        //{
        //    var existingUser = await _userManager.FindByEmailAsync(email);

        //    if (existingUser != null)
        //    {
        //        return new AuthenticationResult
        //        {
        //            Errors = new[] { "User with this email address already exists" }
        //        };
        //    }

        //    var newUserId = Guid.NewGuid();
        //    var newUser = new IdentityUser
        //    {
        //        Id = newUserId.ToString(),
        //        Email = email,
        //        UserName = email
        //    };

        //    var createdUser = await _userManager.CreateAsync(newUser, password);

        //    if (!createdUser.Succeeded)
        //    {
        //        return new AuthenticationResult
        //        {
        //            Errors = createdUser.Errors.Select(x => x.Description)
        //        };
        //    }

        //    return await GenerateAuthenticationResultForUserAsync(newUser);
        //}

        //public async Task<AuthenticationResult> LoginAsync(string email, string password)
        //{
        //    var user = await _userManager.FindByEmailAsync(email);

        //    if (user == null)
        //    {
        //        return new AuthenticationResult
        //        {
        //            Errors = new[] { "User does not exist" }
        //        };
        //    }

        //    var userHasValidPassword = await _userManager.CheckPasswordAsync(user, password);

        //    if (!userHasValidPassword)
        //    {
        //        return new AuthenticationResult
        //        {
        //            Errors = new[] { "User/password combination is wrong" }
        //        };
        //    }

        //    return await GenerateAuthenticationResultForUserAsync(user);
        //}

        //public async Task<AuthenticationResult> RefreshTokenAsync(string token, string refreshToken)
        //{
        //    var validatedToken = GetPrincipalFromToken(token);

        //    if (validatedToken == null)
        //    {
        //        return new AuthenticationResult { Errors = new[] { "Invalid Token" } };
        //    }

        //    var expiryDateUnix =
        //        long.Parse(validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

        //    var expiryDateTimeUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        //        .AddSeconds(expiryDateUnix);

        //    if (expiryDateTimeUtc > DateTime.UtcNow)
        //    {
        //        return new AuthenticationResult { Errors = new[] { "This token hasn't expired yet" } };
        //    }

        //    var jti = validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

        //    var storedRefreshToken = await _context.RefreshTokens.SingleOrDefaultAsync(x => x.Token == refreshToken);

        //    if (storedRefreshToken == null)
        //    {
        //        return new AuthenticationResult { Errors = new[] { "This refresh token does not exist" } };
        //    }

        //    if (DateTime.UtcNow > storedRefreshToken.ExpiryDate)
        //    {
        //        return new AuthenticationResult { Errors = new[] { "This refresh token has expired" } };
        //    }

        //    if (storedRefreshToken.Invalidated)
        //    {
        //        return new AuthenticationResult { Errors = new[] { "This refresh token has been invalidated" } };
        //    }

        //    if (storedRefreshToken.Used)
        //    {
        //        return new AuthenticationResult { Errors = new[] { "This refresh token has been used" } };
        //    }

        //    if (storedRefreshToken.JwtId != jti)
        //    {
        //        return new AuthenticationResult { Errors = new[] { "This refresh token does not match this JWT" } };
        //    }

        //    storedRefreshToken.Used = true;
        //    //_context.RefreshTokens.Update(storedRefreshToken);
        //    //await _context.SaveChangesAsync();

        //    var user = await _userManager.FindByIdAsync(validatedToken.Claims.Single(x => x.Type == "id").Value);
        //    return await GenerateAuthenticationResultForUserAsync(user);
        //}

        //private ClaimsPrincipal GetPrincipalFromToken(string token)
        //{
        //    var tokenHandler = new JwtSecurityTokenHandler();

        //    try
        //    {
        //        var tokenValidationParameters = _tokenValidationParameters.Clone();
        //        tokenValidationParameters.ValidateLifetime = false;
        //        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        //        if (!IsJwtWithValidSecurityAlgorithm(validatedToken))
        //        {
        //            return null;
        //        }

        //        return principal;
        //    }
        //    catch
        //    {
        //        return null;
        //    }
        //}

        //private bool IsJwtWithValidSecurityAlgorithm(SecurityToken validatedToken)
        //{
        //    return (validatedToken is JwtSecurityToken jwtSecurityToken) &&
        //           jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
        //               StringComparison.InvariantCultureIgnoreCase);
        //}

        //private async Task<AuthenticationResult> GenerateAuthenticationResultForUserAsync(IdentityUser user)
        //{
        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

        //    var claims = new List<Claim>
        //    {
        //        new Claim(JwtRegisteredClaimNames.Sub, user.Email),
        //        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        //        new Claim("id", user.Id)
        //    };

        //    var userClaims = await _userManager.GetClaimsAsync(user);
        //    claims.AddRange(userClaims);

        //    var userRoles = await _userManager.GetRolesAsync(user);
        //    foreach (var userRole in userRoles)
        //    {
        //        claims.Add(new Claim(ClaimTypes.Role, userRole));
        //        var role = await _roleManager.FindByNameAsync(userRole);
        //        if (role == null) continue;
        //        var roleClaims = await _roleManager.GetClaimsAsync(role);

        //        foreach (var roleClaim in roleClaims)
        //        {
        //            if (claims.Contains(roleClaim))
        //                continue;

        //            claims.Add(roleClaim);
        //        }
        //    }

        //    var tokenDescriptor = new SecurityTokenDescriptor
        //    {
        //        Subject = new ClaimsIdentity(claims),
        //        Expires = DateTime.UtcNow.Add(_jwtSettings.TokenLifetime),
        //        SigningCredentials =
        //            new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        //    };

        //    var token = tokenHandler.CreateToken(tokenDescriptor);

        //    var refreshToken = new RefreshToken
        //    {
        //        JwtId = token.Id,
        //        UserId = user.Id,
        //        CreationDate = DateTime.UtcNow,
        //        ExpiryDate = DateTime.UtcNow.AddMonths(6)
        //    };

        //    //await _context.RefreshTokens.AddAsync(refreshToken);
        //    //await _context.SaveChangesAsync();

        //    return new AuthenticationResult
        //    {
        //        Success = true,
        //        Token = tokenHandler.WriteToken(token),
        //        RefreshToken = refreshToken.Token
        //    };
        //}
    }
}