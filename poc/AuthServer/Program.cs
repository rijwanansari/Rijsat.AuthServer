
using System.Text;
using AuthServer.Infrastructure;
using AuthServer.Models;
using AuthServer.Services.JwtTokenService;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("logs/authserver-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Add Serilog
    builder.Host.UseSerilog();

    // Add services to the container
    builder.Services.AddControllersWithViews();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    // Add Entity Framework
    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));


    // Add Identity
    builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        // Password settings
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;

        // User settings
        options.User.RequireUniqueEmail = true;
        options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

        // Signin settings
        options.SignIn.RequireConfirmedEmail = false;
        options.SignIn.RequireConfirmedPhoneNumber = false;

        // Lockout settings
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

    // Add JWT Authentication
    var jwtSettings = builder.Configuration.GetSection("JwtSettings");
    var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");

    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ValidateIssuer = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidateAudience = true,
            ValidAudience = jwtSettings["Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            RequireExpirationTime = true
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Log.Warning("JWT Authentication failed: {Error}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Log.Information("JWT Token validated for user: {User}", context.Principal?.Identity?.Name);
                return Task.CompletedTask;
            }
        };
    })
    .AddCookie("Cookies", options =>
    {
        options.LoginPath = "/account/login";
        options.LogoutPath = "/account/logout";
        options.AccessDeniedPath = "/account/accessdenied";
    });

    // Register custom services
    builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();

    // Add CORS
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowSpecificOrigins", policy =>
        {
            policy.WithOrigins("https://localhost:5002", "http://localhost:3000", "https://oauth.pstmn.io")
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        });
    });

    // Add Authorization policies
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
        options.AddPolicy("ManagerOrAdmin", policy => policy.RequireRole("Manager", "Admin"));

        // Permission-based policies
        options.AddPolicy("CanReadUsers", policy =>
            policy.RequireClaim("permission", "users.read"));
        options.AddPolicy("CanWriteUsers", policy =>
            policy.RequireClaim("permission", "users.write"));
    });




    var app = builder.Build();

    // Configure the HTTP request pipeline
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
        app.UseHsts();
    }


    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseRouting();
    app.UseCors("AllowSpecificOrigins");

    app.UseAuthentication();
    app.UseAuthorization();

    // Map routes
    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");

    app.MapControllers();

    // Ensure database is created and seeded
    using (var scope = app.Services.CreateScope())
    {
        var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

        // Ensure database exists
        await context.Database.EnsureCreatedAsync();

        
        context.Database.Migrate();

        // Seed initial data
        await SeedDataAsync(userManager, roleManager, context);
        DbSeeder.Seed(context);
    }

    Log.Information("Starting Authentication Server...");
    app.Run();

}
catch (Exception ex)
{
    Log.Fatal(ex, "Application start-up failed");
    Log.Fatal(ex, "Authentication Server terminated unexpectedly");
    return;
}
finally
{
    Log.CloseAndFlush();
}

static async Task SeedDataAsync(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, AuthDbContext context)
{
    // Seed Admin User
    var adminEmail = "admin@authserver.com";
    var adminUser = await userManager.FindByEmailAsync(adminEmail);
    
    if (adminUser == null)
    {
        adminUser = new ApplicationUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            FirstName = "System",
            LastName = "Administrator",
            EmailConfirmed = true,
            IsActive = true
        };

        var result = await userManager.CreateAsync(adminUser, "Admin123!");
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(adminUser, "Admin");
            Log.Information("Admin user created successfully");
        }
        else
        {
            Log.Error("Failed to create admin user: {Errors}", string.Join(", ", result.Errors.Select(e => e.Description)));
        }
    }

    // Seed Test User
    var testEmail = "user@test.com";
    var testUser = await userManager.FindByEmailAsync(testEmail);
    
    if (testUser == null)
    {
        testUser = new ApplicationUser
        {
            UserName = testEmail,
            Email = testEmail,
            FirstName = "Test",
            LastName = "User",
            EmailConfirmed = true,
            IsActive = true
        };

        var result = await userManager.CreateAsync(testUser, "User123!");
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(testUser, "User");
            Log.Information("Test user created successfully");
        }
    }

    // Ensure all role-permission relationships are created
    await EnsureRolePermissionsAsync(context);

    await context.SaveChangesAsync();
}

static async Task EnsureRolePermissionsAsync(AuthDbContext context)
{
    // Admin gets all permissions
    var adminRoleId = "1";
    var allPermissionIds = await context.Permissions.Select(p => p.Id).ToListAsync();
    
    foreach (var permissionId in allPermissionIds)
    {
        var exists = await context.RolePermissions
            .AnyAsync(rp => rp.RoleId == adminRoleId && rp.PermissionId == permissionId);
            
        if (!exists)
        {
            context.RolePermissions.Add(new RolePermission 
            { 
                RoleId = adminRoleId, 
                PermissionId = permissionId 
            });
        }
    }

    // User gets basic permissions
    var userRoleId = "2";
    var basicPermissions = new[] { 6, 7 }; // api.read, api.write
    
    foreach (var permissionId in basicPermissions)
    {
        var exists = await context.RolePermissions
            .AnyAsync(rp => rp.RoleId == userRoleId && rp.PermissionId == permissionId);
            
        if (!exists)
        {
            context.RolePermissions.Add(new RolePermission 
            { 
                RoleId = userRoleId, 
                PermissionId = permissionId 
            });
        }
    }

    // Manager gets user management permissions
    var managerRoleId = "3";
    var managerPermissions = new[] { 1, 2, 4, 6, 7 }; // users.read, users.write, roles.read, api.read, api.write
    
    foreach (var permissionId in managerPermissions)
    {
        var exists = await context.RolePermissions
            .AnyAsync(rp => rp.RoleId == managerRoleId && rp.PermissionId == permissionId);
            
        if (!exists)
        {
            context.RolePermissions.Add(new RolePermission 
            { 
                RoleId = managerRoleId, 
                PermissionId = permissionId 
            });
        }
    }
}


