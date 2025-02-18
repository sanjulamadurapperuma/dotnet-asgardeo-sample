using System.Security.Claims;

namespace asgardeo_dotnet;

public sealed class UserInfo
{
    public required string UserId { get; init; }
    public required string FirstName { get; init; }
    public required string LastName { get; init; }
    public required string UserName { get; init; }

    public const string UserIdClaimType = "sub";
    public const string FirstNameClaimType = "given_name";
    public const string LastNameClaimType = "family_name";
    public const string UserNameClaimType = "username";

    public static UserInfo FromClaimsPrincipal(ClaimsPrincipal principal) =>
        new()
        {
            UserId = GetRequiredClaim(principal, UserIdClaimType),
            FirstName = GetRequiredClaim(principal, FirstNameClaimType),
            LastName = GetRequiredClaim(principal, LastNameClaimType),
            UserName = GetRequiredClaim(principal, UserNameClaimType),
        };

    public ClaimsPrincipal ToClaimsPrincipal() =>
        new(new ClaimsIdentity(
            [new(UserIdClaimType, UserId), new(FirstNameClaimType, FirstName), new(LastNameClaimType, LastName), new(UserNameClaimType, UserName)],
            authenticationType: nameof(UserInfo),
            nameType: UserNameClaimType,
            roleType: null));

    private static string GetRequiredClaim(ClaimsPrincipal principal, string claimType) =>
        principal.FindFirst(claimType)?.Value ?? throw new InvalidOperationException($"Could not find required '{claimType}' claim.");
}
