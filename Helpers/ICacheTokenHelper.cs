namespace KeycloakAuth.Helpers
{
    public interface ICacheTokenHelper
    {
        public TimeSpan CacheTimeCalc(DateTime validTo);
    }

}
