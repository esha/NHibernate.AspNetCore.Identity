NHibernate.AspNetCore.Identity
==============================

ASP.NET Core 2.0 Identity provider that uses NHibernate for storage

## Purpose

ASP.NET Core 2.0 shipped with yet another rewrite of the Identity system (in the Microsoft.AspNetCore.Identity package) in order to support both local login and remote logins via OpenID/OAuth, but only ships with an
Entity Framework provider (Microsoft.AspNetCore.Identity.EntityFrameworkCore). The changes were significant enough to require another project since NHibernate.AspNet.Identity is incompatible with the new classes.

## Features

* Drop-in replacement ASP.NET Core 2.0 Identity with NHibernate for persistence.
* Based on same schema required by Microsoft.AspNetCore.Identity.EntityFrameworkCore for model compatibility.
* Contains the same IdentityUser class used by the EntityFramework provider in the EntityFrameworkCore project.
* Supports additional profile properties on your application's user model.
* Provides UserStore&lt;TUser&gt; implementation that implements the same interfaces as the EntityFramework version:
    * IUserStore&lt;TUser&gt;
    * IUserLoginStore&lt;TUser&gt;
    * IUserRoleStore&lt;TUser&gt;
    * IUserClaimStore&lt;TUser&gt;
    * IUserLoginStore&lt;TUser&gt;
    * IUserPasswordStore&lt;TUser&gt;
    * IUserSecurityStampStore&lt;TUser&gt;

## Quick-start guide

These instructions assume you know how to set up NHibernate within an MVC application.

1. Create a new ASP.NET Core 2.0 project, choosing the Individual User Accounts authentication type.
2. Remove the Entity Framework packages and replace with NHibernate Identity.
3. In ~/Models/IdentityModels.cs:
    a. Remove the namespace: Microsoft.AspNetCore.Identity.EntityFrameworkCore
    b. Add the namespace: NHibernate.AspNetCore.Identity
    c. Remove the ApplicationDbContext and ApplicationUserContext classes completely.
4. In ~/Controllers/AccountController.cs
    a. Remove the namespace: Microsoft.AspNetCore.Identity.EntityFrameworkCore
    b. Add the relevant ISession implementation that will be used by default.  This could be from a DI implementation.
       Note: This isn't mandatory, if you are using a framework that will inject the dependency, you shouldn't need the parameterless constructor.
5. Setup configuration code

### NHibernate

```C#

  // this assumes you are using the default Identity model of "ApplicationUser"
  var myEntities = new [] {
      typeof(ApplicationUser)
  };

  var configuration = new Configuration();
  configuration.Configure("sqlite-nhibernate-config.xml");
  configuration.AddDeserializedMapping(MappingHelper.GetIdentityMappings(myEntities), null);

  var factory = configuration.BuildSessionFactory();
  var session = factory.OpenSession();

  var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(session);
```

### FluentNHibernate

```C#

  // this assumes you are using the default Identity model of "ApplicationUser"
  var myEntities = new [] {
      typeof(ApplicationUser)
  };

  var configuration = Fluently.Configure()
     .Database(/*.....*/)
     .ExposeConfiguration(cfg => {
         cfg.AddDeserializedMapping(MappingHelper.GetIdentityMappings(myEntities), null);
  });

  var factory = configuration.BuildSessionFactory();
  var session = factory.OpenSession();

  var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(session);
```

## Thanks To

Special thanks to [Antônio Milesi Bastos](https://github.com/milesibastos) whose [NHibernate.AspNet.Identity](https://github.com/nhibernate/NHibernate.AspNet.Identity) project provided the base for jumpstarting the NHibernate ASP.NET Core 2.0 provider.
