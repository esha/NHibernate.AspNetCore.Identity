using NHibernate.Mapping.ByCode.Conformist;

namespace NHibernate.AspNetCore.Identity
{
    public class IdentityUserTokenMap : ClassMapping<IdentityUserToken>
    {
        public IdentityUserTokenMap()
        {
            this.Table("AspNetUserTokens");
            this.ComposedId(map =>
            {
                map.Property(t => t.UserId);
                map.Property(t => t.LoginProvider);
                map.Property(t => t.Name);
            });
            this.Property(x => x.Value, map =>
            {
                map.Length(ushort.MaxValue);
                map.NotNullable(true);
            });
        }
    }
}