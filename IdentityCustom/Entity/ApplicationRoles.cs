namespace IdentityCustom.Entity;

public class ApplicationRoles : BaseEntity
{
    public Guid ApplicationUserId { get; set; }
    public ApplicationUser ApplicationUser { get; set; }
    public string Name { get; set; }
}
