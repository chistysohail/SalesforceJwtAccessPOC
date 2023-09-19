using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace SalesforceJwtAccess
{
    class Program
    {
        private const string ClientId = "ABC123DEF456";
        private const string Audience = "https://login.salesforce.com";
        private const string Subject = "john.doe@example.com";
        private const string PrivateKey = @"-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALmRZl/LsFUrwiFh
... (trimmed for brevity) ...
Nh44dyK8E1R1qDrkjwF2FfE7c5hC2BcekLRTOGw=
-----END PRIVATE KEY-----";

        static async Task Main(string[] args)
        {
            var jwt = GenerateJwtToken();
            var accessToken = await RequestAccessToken(jwt);
            var apiResult = await CallSalesforceApi(accessToken);

            Console.WriteLine($"Salesforce API Result: \n{apiResult}");
        }

        static string GenerateJwtToken()
        {
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(PrivateKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Trim()), out _);

            var securityKey = new RsaSecurityKey(rsa);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Iss, ClientId),
                new Claim(JwtRegisteredClaimNames.Aud, Audience),
                new Claim(JwtRegisteredClaimNames.Sub, Subject),
                // Add other claims as needed
            };

            var token = new JwtSecurityToken(
                issuer: ClientId,
                audience: Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(3),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        static async Task<string> RequestAccessToken(string jwt)
        {
            using HttpClient client = new HttpClient();
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new KeyValuePair<string, string>("assertion", jwt)
            });

            var response = await client.PostAsync("https://login.salesforce.com/services/oauth2/token", content);
            var jsonResponse = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(jsonResponse);
            return tokenResponse.AccessToken;
        }

        static async Task<string> CallSalesforceApi(string accessToken)
        {
            using HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var apiResponse = await client.GetStringAsync("https://YOUR_INSTANCE.salesforce.com/services/data/v53.0/limits/");
            return apiResponse;
        }

        private class TokenResponse
        {
            [JsonPropertyName("access_token")]
            public string AccessToken { get; set; }
        }
    }
}
