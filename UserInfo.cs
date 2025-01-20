using System.Security.Claims;

namespace asgardeo_dotnet;

public sealed class UserInfo
{
    public required string UserId { get; init; }
    public required string Name { get; init; }

    public required string UserName { get; init; }

    public const string UserIdClaimType = "sub";
    public const string NameClaimType = "name";

    public const string UserNameClaimType = "username";

    public static UserInfo FromClaimsPrincipal(ClaimsPrincipal principal) =>
        new()
        {
            UserId = GetRequiredClaim(principal, UserIdClaimType),
            Name = GetRequiredClaim(principal, NameClaimType),
            UserName = GetRequiredClaim(principal, UserNameClaimType),
        };

    public ClaimsPrincipal ToClaimsPrincipal() =>
        new(new ClaimsIdentity(
            [new(UserIdClaimType, UserId), new(NameClaimType, Name), new(UserNameClaimType, UserName)],
            authenticationType: nameof(UserInfo),
            nameType: NameClaimType,
            roleType: null));

    private static string GetRequiredClaim(ClaimsPrincipal principal, string claimType) =>
        principal.FindFirst(claimType)?.Value ?? throw new InvalidOperationException($"Could not find required '{claimType}' claim.");
}
