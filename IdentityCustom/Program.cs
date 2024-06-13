using IdentityCustom.Components;
using IdentityCustom.Components.Account;
using IdentityCustom.Data;

using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

var database = new InMemoryDatabaseRoot();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(o => o.UseInMemoryDatabase(nameof(ApplicationDbContext), database));

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityUserAccessor>();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

builder.Services.AddScoped<IEmailSender<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IUserStore<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IUserValidator<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IUserPasswordStore<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IPasswordHasher<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IPasswordValidator<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IUserLoginStore<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IUserClaimStore<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IUserRoleStore<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IUserSecurityStampStore<IdentityUser>, CustomIdentityManager>();
builder.Services.AddScoped<IRoleStore<IdentityRole>, CustomIdentityManager>();
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
     .AddDefaultTokenProviders();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.Run();
