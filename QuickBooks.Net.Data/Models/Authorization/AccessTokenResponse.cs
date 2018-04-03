using Newtonsoft.Json;

namespace QuickBooks.Net.Data.Models.Authorization
{
    public class AccessTokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
    }
}