using NHibernate.Proxy;

namespace NHibernate.AspNetCore.Identity
{
    internal static class TypeExtensions
    {
        public static bool IsUnproxiedTypeEqual(this System.Type type, System.Type other)
        {
            var otherType = other.GetType();
            var thisType = type.GetType();

            if (otherType != thisType)
            {
                var otherUnproxiedType = other.IsProxy() ? otherType.BaseType : otherType;
                var thisUnproxiedType = type.IsProxy() ? thisType.BaseType : thisType;
                return thisUnproxiedType == otherUnproxiedType;
            }

            return true;
        }
    }
}