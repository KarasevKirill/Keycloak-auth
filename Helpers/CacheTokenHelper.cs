namespace KeycloakAuth.Helpers
{
    public class CacheTokenHelper : ICacheTokenHelper
    {
        public TimeSpan CacheTimeCalc(DateTime validTo)
        {
            return TimeSpan.FromMinutes((validTo - DateTime.UtcNow).Minutes + 1);
        }
    }

}
