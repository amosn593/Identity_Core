using IdentityCoreDemo.Authentication;
using IdentityCoreDemo.Database;
using IdentityCoreDemo.Features;
using IdentityCoreDemo.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();


builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddGoogle(GoogleDefaults.AuthenticationScheme, googleOptions =>
    {
        googleOptions.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
        googleOptions.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
        googleOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters.ValidateIssuer = true;
        options.TokenValidationParameters.ValidateAudience = true;
        options.TokenValidationParameters.ValidateLifetime = true;
        options.TokenValidationParameters.ValidateIssuerSigningKey = true;
        options.TokenValidationParameters.ValidIssuer = builder.Configuration["JWT:Issuer"];
        options.TokenValidationParameters.ValidAudience = builder.Configuration["JWT:Audience"];
        options.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:SecretKey"]!));
    });

builder.Services.AddAuthorization();

builder.Services.AddScoped<TokenGenerator>();

//builder.Services.AddAuthorizationBuilder()
//    .SetFallbackPolicy(new AuthorizationPolicyBuilder()
//        .RequireAuthenticatedUser()
//        .Build())
//    .AddPolicy(Roles.Member, policy =>
//        policy.RequireRole(Roles.Member));


builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

//Light weight for web apis only...
builder.Services.AddIdentityCore<ApplicationUser>(opt =>
        {
            opt.Password.RequireDigit = true;
            opt.Password.RequireLowercase = true;
            opt.Password.RequireNonAlphanumeric = true;
            opt.Password.RequireUppercase = true;
            opt.Password.RequiredLength = 8;
            opt.User.RequireUniqueEmail = true;
        })
        .AddRoles<IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddSignInManager()
        .AddDefaultTokenProviders();

builder.Services.AddCors(opt =>
{
    opt.AddPolicy("CorsPolicy", opt =>
    {
        opt.AllowAnyHeader().AllowAnyMethod().AllowCredentials().WithOrigins("https://localhost:7258/");
    });
});

var app = builder.Build();

app.UseCors("CorsPolicy");

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();

    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    dbContext.Database.Migrate();

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    if (!await roleManager.RoleExistsAsync(Roles.Admin) )
    {
        await roleManager.CreateAsync(new IdentityRole(Roles.Admin));
    }

    if (!await roleManager.RoleExistsAsync(Roles.Cashier))
    {
        await roleManager.CreateAsync(new IdentityRole(Roles.Cashier));
    }
    if (!await roleManager.RoleExistsAsync(Roles.Store))
    {
        await roleManager.CreateAsync(new IdentityRole(Roles.Store));
    }
    if (!await roleManager.RoleExistsAsync(Roles.Accountant))
    {
        await roleManager.CreateAsync(new IdentityRole(Roles.Accountant));
    }
    if (!await roleManager.RoleExistsAsync(Roles.Auditor))
    {
        await roleManager.CreateAsync(new IdentityRole(Roles.Auditor));
    }
    if (!await roleManager.RoleExistsAsync(Roles.Member))
    {
        await roleManager.CreateAsync(new IdentityRole(Roles.Member));
    }
}

app.UseHttpsRedirection();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

RegisterUser.MapEndpoint(app);

LoginUser.MapEndpoint(app);

//app.MapIdentityApi<ApplicationUser>();

app.Run();
