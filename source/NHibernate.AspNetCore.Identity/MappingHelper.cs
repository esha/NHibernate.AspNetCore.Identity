using NHibernate.Cfg.MappingSchema;
using NHibernate.Mapping.ByCode;

namespace NHibernate.AspNetCore.Identity
{
    public static class MappingHelper
    {

        /// <summary>
        /// Gets a mapping that can be used with NHibernate.
        /// </summary>
        /// <param name="additionalTypes">Additional Types that are to be added to the mapping, this is useful for adding your ApplicationUser class</param>
        /// <returns></returns>
        public static HbmMapping GetIdentityMappings(System.Type[] additionalTypes)
        {
            var allEntities = new[] {
                typeof(IdentityUser),
                typeof(IdentityRole),
                typeof(IdentityUserClaim),
                typeof(IdentityUserToken),
                typeof(IdentityUserLogin),
            };

            var mapper = new ModelMapper();
            mapper.AddMapping<IdentityUserMap>();
            mapper.AddMapping<IdentityRoleMap>();
            mapper.AddMapping<IdentityUserClaimMap>();
            mapper.AddMapping<IdentityUserTokenMap>();
            mapper.AddMapping<IdentityUserLoginMap>();

            return mapper.CompileMappingFor(allEntities);
        }
    }
}
