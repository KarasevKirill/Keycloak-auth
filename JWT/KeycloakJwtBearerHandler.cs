using KeycloakAuth.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace KeycloakAuth.JWT
{
    public class KeycloakJwtBearerHandler : JwtBearerHandler
    {
        private const string bearer = "";
        private readonly HttpClient httpClient;
        private readonly IMemoryCache memoryCache;
        private readonly IConfiguration appConfig;
        private readonly ILogger logger;
        private readonly ICacheTokenHelper tokenHelper;

        public KeycloakJwtBearerHandler(
            IOptionsMonitor<JwtBearerOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            HttpClient httpClient,
            IMemoryCache memoryCache,
            IConfiguration appConfig,
            ICacheTokenHelper tokenHelper
        ) : base(options, logger, encoder, clock)
        {
            this.httpClient = httpClient;
            this.memoryCache = memoryCache;
            this.appConfig = appConfig;
            this.logger = logger.CreateLogger("AuthInfo");
            this.tokenHelper = tokenHelper;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Context.Request.Headers.TryGetValue("Authorization", out var authorizationHeaderValues))
            {
                return AuthenticateResult.Fail("Authorization header not found");
            }

            var authorizationHeader = authorizationHeaderValues.FirstOrDefault();

            if (string.IsNullOrEmpty(authorizationHeader) ||
                !authorizationHeader.StartsWith("Bearer ") ||
                authorizationHeader.Length < 50)
            {
                return AuthenticateResult.Fail("Bearer token not found");
            }

            var tokenStr = authorizationHeader.Substring("Bearer ".Length).Trim();

            var cacheKey = "";

            try
            {
                cacheKey = GetCacheKey(tokenStr);
            }
            catch
            {
                return AuthenticateResult.Fail("Invalid token");
            }
            var claims = memoryCache.Get<List<Claim>>(cacheKey);

            if (claims == null || claims.Count == 0)
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenStr);
                HttpResponseMessage response;

                try
                {
                    response = await httpClient.PostAsync(appConfig["AuthServerUserinfo"], null);
                }
                catch (Exception e)
                {
                    logger.LogError($"Connection to auth server failed: {e.Message}");
                    return AuthenticateResult.Fail("Connection to auth server failed");
                }

                if (!response.IsSuccessStatusCode)
                {
                    return AuthenticateResult.Fail("Token validation failed");
                }

                var handler = new JwtSecurityTokenHandler();

                var token = handler.ReadToken(tokenStr) as JwtSecurityToken;

                claims = GetClaims(token);

                if (claims == null || claims.Count == 0)
                {
                    return AuthenticateResult.Fail("User have no roles for this client");
                }

                SetCacheData(cacheKey, claims, token.ValidTo);
            }

            var claimsIdentity = new ClaimsIdentity(claims, "Token");
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            return AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, "CustomJwtBearer"));
        }

        private string GetCacheKey(string token)
        {
            var data = token.Split(".")[1];

            return data.Substring(data.Length - 12, 10);
        }

        private void SetCacheData(string cacheKey, List<Claim> claims, DateTime validTo)
        {
            var options = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = tokenHelper.CacheTimeCalc(validTo)
            };

            memoryCache.Set(cacheKey, claims, options);
        }

        private List<Claim>? GetClaims(JwtSecurityToken? token)
        {
            if (token == null)
            {
                return null;
            }

            var claims = new List<Claim>();

            var claimRoles = token?.Claims.FirstOrDefault(claim => claim.Type == "resource_access");

            if (claimRoles == null || string.IsNullOrEmpty(claimRoles.Value))
            {
                return null;
            }

            foreach (var claim in token.Claims)
            {
                switch (claim.Type)
                {
                    case "name":
                        claims.Add(new Claim(ClaimTypes.Name, claim.Value ?? ""));
                        break;
                    case "email":
                        claims.Add(new Claim(ClaimTypes.Email, claim.Value ?? ""));
                        break;
                    case "preferred_username":
                        claims.Add(new Claim(ClaimTypes.GivenName, claim.Value ?? ""));
                        break;
                }
            }

            var userRoles = JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, string[]>>>(claimRoles.Value);

            var currentClientRoles = userRoles?.GetValueOrDefault(appConfig["ClientId"]);

            if (currentClientRoles == null || currentClientRoles.Count == 0)
            {
                return null;
            }

            var roles = currentClientRoles?.GetValueOrDefault("roles");

            if (roles == null || roles.Length == 0)
            {
                return null;
            }

            for (var i = 0; i < roles.Length; i++)
            {
                claims.Add(new Claim(ClaimTypes.Role, roles[i]));
            }

            return claims;
        }
    }
}
