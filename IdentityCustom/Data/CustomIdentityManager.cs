using IdentityCustom.Entity;

using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

using System.Security.Claims;
using System.Text;

namespace IdentityCustom.Data;



public class CustomIdentityManager(ILogger<CustomIdentityManager> logger, ApplicationDbContext dbContext) :
    IEmailSender<IdentityUser>,
    IPasswordHasher<IdentityUser>,
    IPasswordValidator<IdentityUser>,
    IUserValidator<IdentityUser>,
    IUserStore<IdentityUser>,
    IUserPhoneNumberStore<IdentityUser>,
    IUserEmailStore<IdentityUser>,
    IUserClaimStore<IdentityUser>,
    IUserLoginStore<IdentityUser>,
    IUserRoleStore<IdentityUser>,
    IUserPasswordStore<IdentityUser>,
    IUserSecurityStampStore<IdentityUser>,
    IRoleStore<IdentityRole>
{

    private IdentityUser MapUser(ApplicationUser user) => new()
    {
        Id = user.ExternalId,
        UserName = user.UserName,
        NormalizedUserName = user.NormalizedUserName,
        Email = user.Email,
        NormalizedEmail = user.NormalizedEmail,
        EmailConfirmed = user.EmailConfirmed,
        PasswordHash = user.PasswordHash,
        SecurityStamp = user.SecurityStamp,
        ConcurrencyStamp = user.ConcurrencyStamp,
        PhoneNumber = user.PhoneNumber,
        PhoneNumberConfirmed = user.PhoneNumberConfirmed,
        TwoFactorEnabled = user.TwoFactorEnabled,
        LockoutEnd = user.LockoutEnd,
        LockoutEnabled = user.LockoutEnabled,
        AccessFailedCount = user.AccessFailedCount,
    };


    public async Task SendConfirmationLinkAsync(IdentityUser user, string email, string confirmationLink)
    {
        logger.LogInformation("login email link sent to {email}: {confirmationLink}", email, confirmationLink);
    }

    public async Task SendPasswordResetCodeAsync(IdentityUser user, string email, string resetCode)
    {
        logger.LogInformation("password reset email link sent to {email}, code: {resetCode}", email, resetCode);
    }

    public async Task SendPasswordResetLinkAsync(IdentityUser user, string email, string resetLink)
    {
        logger.LogInformation("password reset link sent to {email}: {confirmationLink}", email, resetLink);
    }

    public async Task AddClaimsAsync(IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task AddLoginAsync(IdentityUser user, UserLoginInfo login, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task AddToRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IdentityResult> CreateAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        localUser.IsReady = true;
        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IdentityResult> DeleteAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
    }

    public async Task<IdentityUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IdentityUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.AsNoTracking().SingleOrDefaultAsync(u => u.ExternalId == userId);
        return localUser is null ? default : MapUser(localUser);
    }

    public async Task<IdentityUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IdentityUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.AsNoTracking().SingleOrDefaultAsync(u => u.NormalizedUserName == normalizedUserName);
        return localUser is null ? default : MapUser(localUser);
    }

    public async Task<IList<Claim>> GetClaimsAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        return [];
    }

    public async Task<string?> GetEmailAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.AsNoTracking().SingleOrDefaultAsync(u => u.ExternalId == user.Id);
        return localUser?.Email;
    }

    public async Task<bool> GetEmailConfirmedAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.AsNoTracking().SingleOrDefaultAsync(u => u.ExternalId == user.Id);
        return localUser?.EmailConfirmed ?? false;
    }

    public async Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<string?> GetNormalizedEmailAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<string?> GetNormalizedRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<string?> GetNormalizedUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<string?> GetPasswordHashAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.AsNoTracking().SingleOrDefaultAsync(u => u.ExternalId == user.Id);
        return localUser?.PasswordHash;
    }

    public async Task<string?> GetPhoneNumberAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser
            .AsNoTracking()
            .Where(u => u.IsReady)
            .SingleOrDefaultAsync(u => u.ExternalId == user.Id);

        return localUser.PhoneNumber;
    }

    public async Task<bool> GetPhoneNumberConfirmedAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<string> GetRoleIdAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<string?> GetRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IList<string>> GetRolesAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        return await dbContext.ApplicationRoles
            .Where(r => r.ApplicationUser.ExternalId == user.Id)
            .Select(r => r.Name)
            .ToListAsync();
    }

    public async Task<string?> GetSecurityStampAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        return localUser.SecurityStamp;
    }

    public async Task<string> GetUserIdAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.AsNoTracking().SingleOrDefaultAsync(u => u.ExternalId == user.Id);
        return localUser?.ExternalId!;
    }

    public async Task<string?> GetUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        return localUser.UserName;
    }

    public async Task<IList<IdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IList<IdentityUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public string HashPassword(IdentityUser user, string password)
    {
        var salt = Encoding.UTF8.GetBytes(user.Id);
        string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password!,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        return hashed;
    }

    public async Task<bool> HasPasswordAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        return localUser is { PasswordHash: not null };
    }

    public async Task<bool> IsInRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task RemoveClaimsAsync(IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task RemoveFromRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task RemoveLoginAsync(IdentityUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task ReplaceClaimAsync(IdentityUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task SetEmailAsync(IdentityUser user, string? email, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        localUser.Email = email;
        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();
    }

    public async Task SetEmailConfirmedAsync(IdentityUser user, bool confirmed, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task SetNormalizedEmailAsync(IdentityUser user, string? normalizedEmail, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        localUser.NormalizedEmail = normalizedEmail;
        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();
    }

    public async Task SetNormalizedRoleNameAsync(IdentityRole role, string? normalizedName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task SetNormalizedUserNameAsync(IdentityUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        localUser.NormalizedUserName = normalizedName;
        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();
    }

    public async Task SetPasswordHashAsync(IdentityUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        localUser.PasswordHash = passwordHash;
        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();
    }

    public async Task SetPhoneNumberAsync(IdentityUser user, string? phoneNumber, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        localUser.PhoneNumber = phoneNumber;
        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();
    }

    public async Task SetPhoneNumberConfirmedAsync(IdentityUser user, bool confirmed, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        localUser.PhoneNumberConfirmed = true;
        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();
    }

    public async Task SetRoleNameAsync(IdentityRole role, string? roleName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task SetSecurityStampAsync(IdentityUser user, string stamp, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);
        localUser.SecurityStamp = stamp;
        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();
    }

    public async Task SetUserNameAsync(IdentityUser user, string? userName, CancellationToken cancellationToken)
    {
        var localUser = new ApplicationUser
        {
            ConcurrencyStamp = user.ConcurrencyStamp,
            ExternalId = user.Id,
            SecurityStamp = user.SecurityStamp,
            UserName = userName,
        };

        await dbContext.ApplicationUser.AddAsync(localUser);
        await dbContext.SaveChangesAsync();
    }

    public async Task<IdentityResult> UpdateAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var localUser = await dbContext.ApplicationUser.SingleAsync(u => u.ExternalId == user.Id);

        localUser.ExternalId = user.Id;
        localUser.UserName = user.UserName;
        localUser.NormalizedUserName = user.NormalizedUserName;
        localUser.Email = user.Email;
        localUser.NormalizedEmail = user.NormalizedEmail;
        localUser.EmailConfirmed = user.EmailConfirmed;
        localUser.PasswordHash = user.PasswordHash;
        localUser.SecurityStamp = user.SecurityStamp;
        localUser.ConcurrencyStamp = user.ConcurrencyStamp;
        localUser.PhoneNumber = user.PhoneNumber;
        localUser.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
        localUser.TwoFactorEnabled = user.TwoFactorEnabled;
        localUser.LockoutEnd = user.LockoutEnd;
        localUser.LockoutEnabled = user.LockoutEnabled;
        localUser.AccessFailedCount = user.AccessFailedCount;

        dbContext.ApplicationUser.Update(localUser);
        await dbContext.SaveChangesAsync();

        return IdentityResult.Success;
    }

    public async Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IdentityResult> ValidateAsync(UserManager<IdentityUser> manager, IdentityUser user, string? password)
    {
        await Task.CompletedTask;
        return password is { Length: > 0 } ?
            IdentityResult.Success :
            IdentityResult.Failed(new IdentityError
            {
                Code = "NOVALIDPASS",
                Description = "Invalid password length"
            });
    }

    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword)
    {
        var localUser = dbContext.ApplicationUser.AsNoTracking().Single(u => u.ExternalId == user.Id);
        return localUser.PasswordHash == hashedPassword ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
    }

    Task<IdentityRole?> IRoleStore<IdentityRole>.FindByIdAsync(string roleId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    Task<IdentityRole?> IRoleStore<IdentityRole>.FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<IdentityResult> ValidateAsync(UserManager<IdentityUser> manager, IdentityUser user)
    {
        var userBeingCreated = await dbContext.ApplicationUser.AsNoTracking().SingleAsync(u => u.ExternalId == user.Id);
        var query = dbContext.ApplicationUser.Where(u => u.IsReady).AsNoTracking();

        if (await query.AnyAsync(u => u.Email == userBeingCreated.Email))
            return IdentityResult.Failed(new IdentityError
            {
                Code = "EMAILNOTUNIQUE",
                Description = "Email is not unique"
            });

        if (await query.AnyAsync(u => u.UserName == userBeingCreated.UserName))
            return IdentityResult.Failed(new IdentityError
            {
                Code = "USERNAMENOTUNIQUE",
                Description = "Username is not unique"
            });

        return IdentityResult.Success;
    }
}
